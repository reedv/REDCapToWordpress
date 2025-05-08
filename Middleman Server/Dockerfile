FROM python:3.10-slim AS build

# Set working directory
WORKDIR /app

# Install security updates and required packages - without pinning to unavailable versions
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates curl openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Update CA certificates
RUN update-ca-certificates

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a smaller runtime image
FROM python:3.10-slim

# Create non-root user with specific UID/GID
RUN groupadd -r -g 10001 wp2redcapuser && useradd -r -g wp2redcapuser -u 10001 wp2redcapuser

# Set working directory
WORKDIR /app

# Install runtime dependencies without pinning versions
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    update-ca-certificates

# Copy installed packages from build stage
COPY --from=build /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

# Copy application files
COPY secure-patient-middleware.py .
COPY config.json .

# Set proper permissions
RUN chown -R wp2redcapuser:wp2redcapuser /app && \
    chmod 750 /app && \
    chmod 640 /app/config.json

# Switch to non-root user
USER wp2redcapuser

# Specify the port the app runs on
ENV PORT=8080

# Add additional security-related environment variables
ENV PYTHONHASHSEED=random \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Command to run the application with proper security settings
CMD ["gunicorn", "--bind", ":8080", \
     "--workers=2", \
     "--threads=4", \
     "--worker-tmp-dir", "/dev/shm", \
     "--worker-class=gthread", \
     "--log-level", "info", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "secure-patient-middleware:app"]