# Stage 1: Compile Tailwind CSS + DaisyUI
FROM node:24.18.0-alpine AS css-builder
WORKDIR /build
COPY package.json package-lock.json ./
COPY static/css/input.css ./static/css/input.css
COPY templates/ ./templates/
RUN npm ci --ignore-scripts && \
    ./node_modules/.bin/tailwindcss -i ./static/css/input.css -o ./static/css/theme.css --minify

# Stage 2: Runtime image
FROM python:3.13-alpine

# install curl for healthcheck
RUN apk add --no-cache curl

# Scanners copied from their official images (avoids `curl | sh`). Dependabot's
# docker ecosystem keeps these tags current. Pinning the binary does NOT freeze
# the vuln DB — Trivy/Xeol fetch that at scan time.
COPY --from=aquasec/trivy:0.76.1 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=noqcks/xeol:v0.10.8 /xeol /usr/local/bin/xeol

# Create a non-root user and corresponding volume folder
RUN adduser -D dockinv; mkdir -p /data; chown dockinv /data

# Create a working directory and copy files
WORKDIR /app
COPY --chown=dockinv:dockinv . .

# Copy compiled CSS from build stage
COPY --chown=dockinv:dockinv --from=css-builder /build/static/css/theme.css ./static/css/theme.css

USER dockinv

# Install dependencies
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.txt

# Set the PATH
ENV PATH=/home/dockinv/.local/bin:$PATH
ENV PYTHONPATH="${PYTHONPATH}:/app"

# Expose the port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s CMD curl -f "http://localhost:8000/health" || exit 1

# Run the application
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:create_app()", "--workers=4"]
