FROM node:16-slim

# Install system packages
RUN apt-get update && \
    apt-get install -y \
      curl \
      wget \
      rsyslog \
      tcpdump \
      net-tools \
      procps \
      vim \
      nano \
      supervisor \
      cron \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /app /var/log /opt/scripts /opt/output /data/raw

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including potentially malicious ones)
RUN npm install

# Copy application files
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ /opt/scripts/

# Copy startup script
COPY scripts/start_api.sh /usr/local/bin/start_api.sh
RUN chmod +x /usr/local/bin/start_api.sh

# Set up environment
ENV NODE_ENV=production
ENV SERVICE_NAME=securitylogs-backend-api
ENV SCENARIO_TYPE=backend-api
ENV API_PORT=3000

# Expose port
EXPOSE 3000

# Start application
CMD ["/usr/local/bin/start_api.sh"] 