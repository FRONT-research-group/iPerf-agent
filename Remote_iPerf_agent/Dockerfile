FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iperf \
    iperf3 \
    iproute2 \
    net-tools \
    iputils-ping \
    mptcpize \
    procps \
    curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000         
EXPOSE 5001/tcp     
EXPOSE 5001/udp     

CMD ["flask", "run", "-h", "0.0.0.0"]
