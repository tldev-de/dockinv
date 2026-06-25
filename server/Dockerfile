# Stage 1: Compile Tailwind CSS + DaisyUI
FROM node:20-alpine AS css-builder
WORKDIR /build
COPY package.json package-lock.json ./
COPY static/css/input.css ./static/css/input.css
COPY templates/ ./templates/
COPY tailwind.config.js ./
RUN npm ci && \
    npx tailwindcss -i ./static/css/input.css -o ./static/css/theme.css --minify

# Stage 2: Runtime image
FROM python:3.13-alpine

# install curl for healthcheck
RUN apk add --no-cache curl

# Install scanner binaries
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/xeol-io/xeol/main/install.sh | sh -s -- -b /usr/local/bin

# Create a non-root user and corresponding volume folder
RUN adduser -D dockinv; mkdir -p /data; chown dockinv /data

# Create a working directory and copy files
WORKDIR /app
COPY --chown=dockinv:dockinv . .

# Copy compiled CSS from build stage
COPY --chown=dockinv:dockinv --from=css-builder /build/static/css/theme.css ./static/css/theme.css

USER dockinv

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

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
