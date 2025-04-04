FROM python:3.10-slim

WORKDIR /app

# Install CA certificates, curl and openssl
RUN apt-get update && \
    apt-get install -y ca-certificates curl openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN update-ca-certificates

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY secure-patient-middleware.py .
COPY config.json .

# Specify the port the app runs on
ENV PORT 8080

# Command to run the application
CMD exec gunicorn --bind :$PORT --log-level debug --access-logfile - --error-logfile - secure-patient-middleware:app
#CMD exec gunicorn --bind :$PORT secure-patient-middleware:app
