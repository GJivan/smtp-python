FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir aiosmtpd==1.4.4

# Create log directory
RUN mkdir -p /var/log && touch /var/log/smtp-relay.log && chmod 666 /var/log/smtp-relay.log

# Create directory for TLS certificates
RUN mkdir -p /etc/certs

# Copy application code
COPY smtp_relay.py /app/

# Make script executable
RUN chmod +x /app/smtp_relay.py

# Expose SMTP port (default: 1025)
EXPOSE 1025

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD nc -z localhost ${LISTEN_PORT:-1025} || exit 1

# Set environment variables (these are defaults, override when running the container)
ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=1025 \
    USE_TLS=False \
    TLS_CERT_FILE=/etc/certs/server.crt \
    TLS_KEY_FILE=/etc/certs/server.key \
    SMTP_AUTH_USERNAME=user \
    SMTP_AUTH_PASSWORD=password \
    ALLOWED_FROM_DOMAINS=example.com \
    ALLOWED_TO_DOMAINS=example.com \
    RELAY_HOST=smtp.example.com \
    RELAY_PORT=25 \
    RELAY_USE_TLS=True \
    RELAY_USE_SSL=False \
    MAX_CONNECTIONS=50 \
    TIMEOUT=60

# Run the application
CMD ["python", "/app/smtp_relay.py"]
