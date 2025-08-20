# Base image
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential gcc libssl-dev pkg-config curl ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/*

# Rust for building native extensions
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy your repository files first (includes templates/)
COPY . .

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip setuptools wheel
RUN pip install -r requirements.txt

# Clone liboqs and liboqs-python, then install liboqs-python
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && pip install . && cd ..

# Install Gunicorn for production Flask server
RUN pip install gunicorn

# Expose Railway port
ENV PORT=8000
EXPOSE 8000

# Use Gunicorn to run Flask in production
CMD ["sh", "-c", "gunicorn main:app --bind 0.0.0.0:$PORT"]
