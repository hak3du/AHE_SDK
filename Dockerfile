# Use a lightweight Python 3.11 base image
FROM python:3.11-slim

# Install system dependencies (git, build tools, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential gcc libssl-dev pkg-config curl ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (needed for pydantic-core, liboqs)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory inside container
WORKDIR /app

# Clone and install liboqs-python BEFORE copying your app (leverages Docker cache)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && pip install . && cd ..

# Copy the entire repository, including frontend, into the container
COPY . .

# Upgrade pip and install Python dependencies from requirements.txt
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Expose the port that Railway will use (default fallback 8000)
ENV PORT=8000
EXPOSE 8000

# Run your Flask app
CMD ["python", "main.py"]
