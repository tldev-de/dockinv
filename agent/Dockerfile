FROM python:3.12-alpine

# install curl for healthcheck
RUN apk add --no-cache curl

# Create a working directory and copy files
WORKDIR /app
COPY * .

# this container must run as root to access the docker socket

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV DOCKER_HOST=unix:///var/run/docker.sock
#ENV HTTP_TOKEN
ENV HTTP_PORT=9999

# Expose the port
EXPOSE ${HTTP_PORT}

# Healthcheck
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s CMD curl -f "http://localhost:${HTTP_PORT}/health" || exit

# Run the application
CMD ["python", "agent.py"]