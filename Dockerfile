FROM python:3.10-slim

WORKDIR /app

# Install system utilities & python deps
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements & install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy logic
COPY . .

# Expose web interface
EXPOSE 8080

# Run Flask
ENV FLASK_HOST="0.0.0.0"
CMD ["python", "aegis.py"]
