FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    HOMELAB_DECK_DATA_DIR=/data

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        openssh-client \
        sshpass \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
