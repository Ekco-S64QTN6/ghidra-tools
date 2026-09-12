# Dockerfile for ghidra-report containerized deployment
FROM eclipse-temurin:21-jdk-jammy

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=11.1.2_PUBLIC
ENV GHIDRA_DATE=20240709
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    sqlite3 \
    curl \
    unzip \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
RUN curl -sSL -o /tmp/ghidra.zip \
    https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_* ${GHIDRA_INSTALL_DIR} \
    && rm /tmp/ghidra.zip

# Create working directory
WORKDIR /workspace

# Copy toolkit repository
COPY . /workspace

RUN chmod +x /workspace/ghidra-report.sh /workspace/tests/run_tests.sh

# Expose web dashboard port
EXPOSE 8080

# Default entrypoint: show help or launch dashboard
ENTRYPOINT ["/workspace/ghidra-report.sh"]
CMD ["--dashboard", "8080"]
