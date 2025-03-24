# SMTP Relay/Proxy

A secure, containerized SMTP relay/proxy that filters emails based on domain rules and forwards valid messages to an actual SMTP server.

## Features

- **Authentication**: Requires username and password for sending emails
- **Domain Filtering**: Checks TO and FROM email domains against allowlists
- **Logging**: Detailed logging of all operations, including warnings for non-allowed domains
- **Secure Forwarding**: Supports TLS/SSL for communication with the actual SMTP server
- **Containerized**: Ready to deploy using Docker
- **Configurable**: Easily configurable through environment variables

## Requirements

- Docker and Docker Compose
- (Optional) SSL/TLS certificates if you want to enable TLS

## Quick Start

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd smtp-relay
   ```

2. Copy your SMTP relay script:
   ```bash
   # Save the provided smtp_relay.py script to the current directory
   ```

3. Create directories for certificates and logs:
   ```bash
   mkdir -p certs logs
   ```

4. (Optional) If you want to use TLS, add your certificates:
   ```bash
   cp your-cert.crt certs/server.crt
   cp your-key.key certs/server.key
   ```

5. Edit the `docker-compose.yml` file to configure your settings:
   - Update authentication credentials
   - Set allowed domains
   - Configure relay server details

6. Build and start the container:
   ```bash
   docker-compose up -d
   ```

7. Check the logs to verify it's working:
   ```bash
   docker-compose logs -f
   ```

## Configuration Options

All configuration is done through environment variables:

### Authentication
- `SMTP_AUTH_USERNAME`: Username required for authentication (default: `user`)
- `SMTP_AUTH_PASSWORD`: Password required for authentication (default: `password`)

### Domain Filtering
- `ALLOWED_FROM_DOMAINS`: Comma-separated list of allowed sender domains (default: `example.com`)
- `ALLOWED_TO_DOMAINS`: Comma-separated list of allowed recipient domains (default: `example.com`)

### Server Configuration
- `LISTEN_HOST`: IP address to listen on (default: `0.0.0.0`)
- `LISTEN_PORT`: Port to listen on (default: `1025`)
- `USE_TLS`: Whether to use TLS for incoming connections (default: `False`)
- `TLS_CERT_FILE`: Path to TLS certificate file (default: `/etc/certs/server.crt`)
- `TLS_KEY_FILE`: Path to TLS key file (default: `/etc/certs/server.key`)

### Relay Configuration
- `RELAY_HOST`: Hostname of the actual SMTP server (default: `smtp.example.com`)
- `RELAY_PORT`: Port of the actual SMTP server (default: `25`)
- `RELAY_USE_TLS`: Whether to use STARTTLS with the relay server (default: `True`)
- `RELAY_USE_SSL`: Whether to use SSL/TLS from the start with the relay server (default: `False`)
- `RELAY_USERNAME`: Username for the relay server (optional)
- `RELAY_PASSWORD`: Password for the relay server (optional)

### Performance
- `MAX_CONNECTIONS`: Maximum number of simultaneous connections (default: `50`)
- `TIMEOUT`: Timeout in seconds for SMTP operations (default: `60`)

## Architecture

The SMTP relay consists of the following components:

1. **SMTPAuthHandler**: Handles authentication of clients
2. **SMTPRelayHandler**: Processes email messages, checks domains, and relays to the actual server
3. **SMTPRelayServer**: Main server class that ties everything together

The flow of an email through the system:

1. Client connects and authenticates
2. Client submits an email
3. Server checks the FROM domain against the allowlist
4. Server checks all TO domains against the allowlist
5. If all checks pass, the email is forwarded to the actual SMTP server
6. If any check fails, a warning is logged and the email is rejected

## Monitoring and Maintenance

### Logs
Logs are stored in `/var/log/smtp-relay.log` inside the container and mapped to `./logs/smtp-relay.log` on the host.

### Troubleshooting
- Check the logs for any errors or warnings
- Verify connectivity to the relay server
- Ensure your authentication credentials are correct

### Testing
You can test the relay using a command-line SMTP client like `swaks`:

```bash
swaks --server localhost:1025 \
      --auth-user myuser --auth-password mypassword \
      --from sender@company.com \
      --to recipient@company.com \
      --header "Subject: Test Email" \
      --body "This is a test email."
```

## Security Considerations

- Store passwords securely (consider using Docker secrets for production)
- Regularly update the container image to get security updates
- Consider using a non-root user in the container
- Always use TLS for production environments

## Error Handling

The relay includes comprehensive error handling:
- Connection errors with the relay server
- Authentication failures
- Domain validation errors
- Message parsing issues
- Timeout handling
- Graceful shutdown on interruption

## Best Practices

1. Always use authentication
2. Use specific domain allowlists, not wildcards
3. Enable TLS for production environments
4. Regularly monitor logs for suspicious activity
5. Set reasonable connection limits to prevent DoS
6. Use a dedicated user for the relay service
