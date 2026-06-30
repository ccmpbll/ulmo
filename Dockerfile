FROM debian:bookworm-slim

ARG VERSION=dev
ENV PYTHONUNBUFFERED=1 \
    ULMO_DATA_DIR=/data \
    ULMO_VERSION=$VERSION \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        git \
        openssh-client \
        sshpass \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
