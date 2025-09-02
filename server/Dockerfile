FROM python:3.13-alpine

# Install dependencies and required libraries
RUN apk add --no-cache curl libstdc++ libgcc

# Install scanner binaries
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/xeol-io/xeol/main/install.sh | sh -s -- -b /usr/local/bin

# Create app directories and non-root user
RUN adduser -D dockinv && \
    mkdir -p /data /app/server/static/css && \
    chown -R dockinv:dockinv /data /app

# Set working directory
WORKDIR /app

# Copy project files as dockinv
COPY --chown=dockinv:dockinv . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Switch to non-root user
USER dockinv

# Build Tailwind CSS (ensure daisyui.css exists in static/css)
WORKDIR /app/server/static/css
RUN curl -sLo tailwindcss https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64-musl && \
    curl -sLO https://github.com/saadeghi/daisyui/releases/latest/download/daisyui.js && \
    chmod +x tailwindcss && \
    ./tailwindcss -i daisyui.css -o theme.css

# Set environment variables
ENV PATH=/home/dockinv/.local/bin:$PATH
ENV PYTHONPATH="${PYTHONPATH}:/app"

# Expose port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s CMD curl -f "http://localhost:8000/health" || exit

# Entrypoint and default command
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:create_app()", "--workers=4"]