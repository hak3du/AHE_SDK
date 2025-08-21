# Use a lightweight Python 3.11 base image
FROM python:3.11-slim

# Install system dependencies including cmake and git
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential gcc libssl-dev pkg-config curl ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/*

# Install Rust for building native Rust extensions like pydantic-core and liboqs
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory inside container
WORKDIR /app

# Clone liboqs and liboqs-python, then install liboqs-python BEFORE copying your app
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && pip install . && cd ..

# Copy your repo files into the container AFTER the above to leverage cache
COPY . .

# Set default port env variable (Render sets PORT dynamically but this is fallback)
ENV PORT=8000

# Upgrade pip and install Python dependencies from requirements.txt
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Expose port 8000 for your API server
EXPOSE 8000

# Run your API with uvicorn, binding explicitly to port 8000 (which matches PORT env)
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
