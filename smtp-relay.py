#!/usr/bin/env python3
"""
SMTP Relay/Proxy Server

This program implements an SMTP relay/proxy that:
1. Requires authentication (username and password)
2. Checks TO and FROM email domains against allowlists
3. Logs warnings for non-allowed domains and ignores those messages
4. Forwards valid emails to the actual SMTP server

"""

import asyncio
import logging
import os
import re
import smtplib
import ssl
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, AUTH, LoginPassword
from email.parser import Parser
from email.policy import default
from typing import List, Optional, Tuple, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/smtp-relay.log')
    ]
)
logger = logging.getLogger('smtp-relay')

# Configuration (can be overridden with environment variables)
CONFIG = {
    # Auth configuration
    'REQUIRE_AUTH': True,
    'AUTH_USERNAME': os.environ.get('SMTP_AUTH_USERNAME', 'user'),
    'AUTH_PASSWORD': os.environ.get('SMTP_AUTH_PASSWORD', 'password'),
    
    # Domain configuration
    'ALLOWED_FROM_DOMAINS': set(os.environ.get('ALLOWED_FROM_DOMAINS', 'example.com').split(',')),
    'ALLOWED_TO_DOMAINS': set(os.environ.get('ALLOWED_TO_DOMAINS', 'example.com').split(',')),
    
    # Server configuration
    'LISTEN_HOST': os.environ.get('LISTEN_HOST', '0.0.0.0'),
    'LISTEN_PORT': int(os.environ.get('LISTEN_PORT', 1025)),
    'USE_TLS': os.environ.get('USE_TLS', 'False').lower() == 'true',
    'TLS_CERT_FILE': os.environ.get('TLS_CERT_FILE', '/etc/certs/server.crt'),
    'TLS_KEY_FILE': os.environ.get('TLS_KEY_FILE', '/etc/certs/server.key'),
    
    # Relay configuration
    'RELAY_HOST': os.environ.get('RELAY_HOST', 'smtp.example.com'),
    'RELAY_PORT': int(os.environ.get('RELAY_PORT', 25)),
    'RELAY_USE_TLS': os.environ.get('RELAY_USE_TLS', 'True').lower() == 'true',
    'RELAY_USE_SSL': os.environ.get('RELAY_USE_SSL', 'False').lower() == 'true',
    'RELAY_USERNAME': os.environ.get('RELAY_USERNAME', None),
    'RELAY_PASSWORD': os.environ.get('RELAY_PASSWORD', None),
    
    # Performance configuration
    'MAX_CONNECTIONS': int(os.environ.get('MAX_CONNECTIONS', 50)),
    'TIMEOUT': int(os.environ.get('TIMEOUT', 60)),
}


class SMTPAuthHandler:
    """Handle SMTP authentication."""
    
    def __init__(self, username: str, password: str):
        """
        Initialize with required credentials.
        
        Args:
            username: The expected username
            password: The expected password
        """
        self.username = username
        self.password = password
    
    def __call__(self, server, session, envelope, mechanism, auth_data):
        """
        Validate provided credentials against expected ones.
        
        Returns:
            AUTH success or failure
        """
        success = False
        
        if mechanism == b'PLAIN':
            # PLAIN auth format: \0username\0password
            try:
                # Extract auth parts from PLAIN auth string
                auth_parts = auth_data.split(b'\0')
                if len(auth_parts) == 3:
                    username = auth_parts[1].decode('utf-8')
                    password = auth_parts[2].decode('utf-8')
                    if username == self.username and password == self.password:
                        success = True
            except Exception as e:
                logger.error(f"Auth error with PLAIN mechanism: {e}")
        
        elif mechanism == b'LOGIN':
            # LOGIN auth is a two-step process handled by LoginPassword
            if isinstance(auth_data, LoginPassword):
                username = auth_data.login.decode('utf-8')
                password = auth_data.password.decode('utf-8')
                if username == self.username and password == self.password:
                    success = True
        
        # Log authentication attempts (keeping passwords private)
        if success:
            logger.info(f"Authentication successful for user: {self.username}")
        else:
            logger.warning(f"Authentication failed for mechanism: {mechanism}")
        
        return success


class SMTPRelayHandler:
    """Process and relay SMTP messages."""
    
    def __init__(self, config: dict):
        """
        Initialize the relay handler with configuration.
        
        Args:
            config: Dictionary with configuration parameters
        """
        self.config = config
        self.parser = Parser(policy=default)
    
    async def handle_DATA(self, server, session, envelope):
        """
        Process the email data, check domains, and relay if valid.
        
        Args:
            server: SMTP server instance
            session: SMTP session information
            envelope: SMTP envelope containing mail data
            
        Returns:
            SMTP response string
        """
        # Check authentication if required
        if self.config['REQUIRE_AUTH'] and not session.authenticated:
            logger.warning(f"Unauthenticated attempt to send mail from {envelope.mail_from}")
            return '530 Authentication required'
        
        # Extract and validate email addresses
        from_domain = self._extract_domain(envelope.mail_from)
        to_domains = [self._extract_domain(rcpt) for rcpt in envelope.rcpt_tos]
        
        # Check FROM domain
        if from_domain not in self.config['ALLOWED_FROM_DOMAINS']:
            logger.warning(f"Rejected mail from non-allowed domain: {from_domain}")
            return '550 Sender domain not allowed'
        
        # Check TO domains
        invalid_to_domains = [domain for domain in to_domains 
                             if domain not in self.config['ALLOWED_TO_DOMAINS']]
        if invalid_to_domains:
            logger.warning(f"Rejected mail to non-allowed domains: {', '.join(invalid_to_domains)}")
            return '550 Recipient domain(s) not allowed'
        
        # Parse the message for additional checks if needed
        message_data = envelope.content.decode('utf-8', errors='replace')
        email_message = self.parser.parsestr(message_data)
        
        # Log the message details (for debugging, can be removed in production)
        logger.info(f"Processing message: Subject='{email_message.get('Subject', '<no subject>')}', "
                   f"From={envelope.mail_from}, To={envelope.rcpt_tos}")
        
        # Attempt to relay the message
        try:
            await self._relay_message(envelope)
            logger.info(f"Successfully relayed message from {envelope.mail_from} to {envelope.rcpt_tos}")
            return '250 OK Message accepted for delivery'
        except Exception as e:
            logger.error(f"Error relaying message: {e}")
            return '451 Requested action aborted: local error in processing'
    
    def _extract_domain(self, email: str) -> str:
        """
        Extract domain part from an email address.
        
        Args:
            email: Email address
            
        Returns:
            Domain part of the email address
        """
        # Handle empty email
        if not email:
            return ""
        
        # Simple regex to extract domain
        match = re.search(r'@([^@]+)$', email)
        if match:
            return match.group(1).lower()
        return ""
    
    async def _relay_message(self, envelope) -> None:
        """
        Forward the message to the actual SMTP server.
        
        Args:
            envelope: SMTP envelope containing mail data
            
        Raises:
            Exception: If relay fails
        """
        # Use a separate thread for blocking SMTP operations
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._send_smtp, envelope.mail_from, envelope.rcpt_tos, envelope.content
        )
    
    def _send_smtp(self, sender: str, recipients: List[str], message: bytes) -> None:
        """
        Send an email via SMTP.
        
        Args:
            sender: Sender email address
            recipients: List of recipient email addresses
            message: Raw message content
            
        Raises:
            smtplib.SMTPException: If sending fails
        """
        # Choose appropriate SMTP client based on configuration
        if self.config['RELAY_USE_SSL']:
            smtp_class = smtplib.SMTP_SSL
            context = ssl.create_default_context()
        else:
            smtp_class = smtplib.SMTP
            context = None
        
        # Connect to the relay server
        with smtp_class(
            host=self.config['RELAY_HOST'],
            port=self.config['RELAY_PORT'],
            timeout=self.config['TIMEOUT']
        ) as server:
            # Set up TLS if required
            if self.config['RELAY_USE_TLS'] and not self.config['RELAY_USE_SSL']:
                server.starttls(context=context)
            
            # Authenticate if credentials are provided
            if self.config['RELAY_USERNAME'] and self.config['RELAY_PASSWORD']:
                server.login(self.config['RELAY_USERNAME'], self.config['RELAY_PASSWORD'])
            
            # Send the message
            server.sendmail(sender, recipients, message)


class SMTPRelayServer:
    """SMTP Relay Server implementation."""
    
    def __init__(self, config: dict):
        """
        Initialize the SMTP relay server.
        
        Args:
            config: Dictionary with configuration parameters
        """
        self.config = config
        self.server = None
        self.controller = None
    
    def start(self) -> None:
        """Start the SMTP relay server."""
        # Create handler instances
        auth_handler = SMTPAuthHandler(
            self.config['AUTH_USERNAME'],
            self.config['AUTH_PASSWORD']
        )
        relay_handler = SMTPRelayHandler(self.config)
        
        # Configure server
        self.server = SMTP(self.config['MAX_CONNECTIONS'])
        
        # Set up authentication
        if self.config['REQUIRE_AUTH']:
            self.server.auth_require_tls = self.config['USE_TLS']
            self.server.auth_callback = auth_handler
        
        # Set up DATA handler
        self.server.data_handler = relay_handler.handle_DATA
        
        # Create the controller
        self.controller = Controller(
            self.server,
            hostname=self.config['LISTEN_HOST'],
            port=self.config['LISTEN_PORT']
        )
        
        # Set up TLS if needed
        if self.config['USE_TLS']:
            self.controller.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.controller.ssl_context.load_cert_chain(
                self.config['TLS_CERT_FILE'], 
                self.config['TLS_KEY_FILE']
            )
        
        # Start the server
        self.controller.start()
        logger.info(f"SMTP Relay server started on {self.config['LISTEN_HOST']}:{self.config['LISTEN_PORT']}")
    
    def stop(self) -> None:
        """Stop the SMTP relay server."""
        if self.controller:
            self.controller.stop()
            logger.info("SMTP Relay server stopped")


def main():
    """Main entry point for the SMTP relay server."""
    try:
        # Initialize and start the server
        server = SMTPRelayServer(CONFIG)
        server.start()
        
        # Run forever
        logger.info("Server is running. Press Ctrl+C to stop.")
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        # Clean shutdown
        try:
            server.stop()
        except:
            pass


if __name__ == "__main__":
    main()
