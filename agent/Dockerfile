FROM python:3.12-alpine

WORKDIR /app
COPY * .

RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV DOCKER_HOST=unix:///var/run/docker.sock
#ENV HTTP_TOKEN
ENV HTTP_PORT=9999

EXPOSE 9999

CMD ["python", "main.py"]