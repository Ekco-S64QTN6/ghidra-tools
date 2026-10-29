# Dockerfile for ghidra-report containerized deployment
FROM eclipse-temurin:25-jdk-jammy

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=12.2_PUBLIC
ENV GHIDRA_DATE=20261016
ENV GHIDRA_SHA256=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-yaml \
    python3-jsonschema \
    sqlite3 \
    curl \
    unzip \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
RUN curl -fsSL --retry 3 --retry-delay 2 -o /tmp/ghidra.zip \
    https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_* "${GHIDRA_INSTALL_DIR}" \
    && rm -f /tmp/ghidra.zip

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
