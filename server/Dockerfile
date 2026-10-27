# Stage 1: Compile Tailwind CSS + DaisyUI
FROM node:24.18.0-alpine AS css-builder
WORKDIR /build
COPY package.json package-lock.json ./
COPY static/css/input.css ./static/css/input.css
COPY templates/ ./templates/
RUN npm ci && \
    ./node_modules/.bin/tailwindcss -i ./static/css/input.css -o ./static/css/theme.css --minify

# Stage 2: Runtime image
FROM python:3.13-alpine

# install curl for healthcheck
RUN apk add --no-cache curl

# Install the scanners from pinned, checksum-verified release tarballs (replaces
# `curl | sh`). Pinning the binary does NOT freeze the vuln DB — Trivy/Xeol fetch
# that at scan time. The `# renovate:` comments let Renovate bump these versions.
# renovate: datasource=github-releases depName=aquasecurity/trivy
ARG TRIVY_VERSION=0.76.1
# renovate: datasource=github-releases depName=xeol-io/xeol
ARG XEOL_VERSION=0.10.8
RUN set -eux; cd /tmp; \
    curl -sfLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    curl -sfLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C /usr/local/bin trivy; \
    curl -sfLO "https://github.com/xeol-io/xeol/releases/download/v${XEOL_VERSION}/xeol_${XEOL_VERSION}_linux_amd64.tar.gz"; \
    curl -sfLO "https://github.com/xeol-io/xeol/releases/download/v${XEOL_VERSION}/xeol_${XEOL_VERSION}_checksums.txt"; \
    grep "xeol_${XEOL_VERSION}_linux_amd64.tar.gz\$" "xeol_${XEOL_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "xeol_${XEOL_VERSION}_linux_amd64.tar.gz" -C /usr/local/bin xeol; \
    rm -f /tmp/trivy_* /tmp/xeol_*

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
