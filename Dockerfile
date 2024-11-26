# Build Stage
FROM ubuntu:latest AS build

# Update and install necessary build tools
RUN apt update && apt install -y \
    curl unzip git wget python3 python3-pip build-essential \
    && wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz \
    && rm -f go1.23.2.linux-amd64.tar.gz \
    && apt clean && rm -rf /var/lib/apt/lists/*

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Install Python dependencies without cache

# Install Go tools
RUN go install github.com/tomnomnom/qsreplace@latest


FROM python:3.10-slim
RUN apt update && apt install git -y && apt clean && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir b-hunters==1.1.4 uro
COPY --from=build /usr/local/go /usr/local/go
COPY --from=build /root/go/bin /root/go/bin

RUN git clone https://github.com/vladko312/SSTImap /root/SSTImap/
RUN git clone https://github.com/vladko312/extras /root/SSTImap/plugins/extras
RUN pip install --no-cache-dir -r /root/SSTImap/requirements.txt
WORKDIR /app/service
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

COPY sstichecker /app/service/sstichecker
CMD [ "python", "-m", "sstichecker" ]