FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy files
COPY . /app

# Install dependencies
RUN pip install -r requirements.txt

# Ensure that output directory exists in container
RUN mkdir -p /output

# Entry point
ENTRYPOINT ["python", "main.py"]
