FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install essential network diagnostic tools and build dependencies for Scapy / libpcap
RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools \
    iputils-ping \
    tcpdump \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python requirements
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Keep container running for interactive or scripted execution
CMD ["tail", "-f", "/dev/null"]
