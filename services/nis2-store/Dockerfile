FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl bind9-dnsutils ca-certificates \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi-dev shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 5000
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["gunicorn", "wsgi:app", "--worker-class", "gthread", "--workers", "1", "--threads", "8", "--bind", "0.0.0.0:5000", "--timeout", "120"]
