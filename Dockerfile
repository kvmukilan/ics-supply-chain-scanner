FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and sample inputs
COPY *.py ./
COPY sample_inventory.csv sample_sbom_cyclonedx.json ./

# Create output and cache directories
RUN mkdir -p output .cache

# Expose API port
EXPOSE 8000

# Default: run the API server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
