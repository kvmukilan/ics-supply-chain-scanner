FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export PIP_CERT=/run/secrets/proxy_ca; fi; \
    pip install --no-cache-dir -r requirements.txt

# Copy application
COPY *.py ./
COPY sample_inventory.csv .

# Create output and cache directories
RUN useradd --create-home --uid 10001 scanner \
    && mkdir -p output .cache \
    && chown -R scanner:scanner /app
USER scanner

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=3)"

# Expose API port
EXPOSE 8000

# Default: run the API server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
