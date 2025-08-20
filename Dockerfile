# Base image
FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential gcc libssl-dev pkg-config curl ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/*

# Rust for building native extensions
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Clone liboqs and liboqs-python
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && pip install . && cd ..

RUN pip install gunicorn

# Copy repository files (including templates/)
COPY . .

# Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Expose Railway port
ENV PORT=8000
EXPOSE 8000

# Use Gunicorn for production Flask serving
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "main:app"]
