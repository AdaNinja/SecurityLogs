FROM nginx:alpine

# Install Node.js and npm for Juice Shop
RUN apk add --no-cache nodejs npm

# Create directory for Juice Shop
RUN mkdir -p /juice-shop

# Download and install Juice Shop
RUN npm install -g juice-shop

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create startup script
RUN echo '#!/bin/sh' > /start.sh && \
    echo 'echo "Starting Juice Shop..."' >> /start.sh && \
    echo 'juice-shop --port 3000 &' >> /start.sh && \
    echo 'echo "Starting Nginx..."' >> /start.sh && \
    echo 'nginx -g "daemon off;"' >> /start.sh && \
    chmod +x /start.sh

# Expose port 80
EXPOSE 80

# Start both Juice Shop and Nginx
CMD ["/start.sh"] 