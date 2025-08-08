# Use official Python 3.11 slim image
FROM python:3.11-slim

# Install dependencies: git, curl, build tools, libssl, pkg-config
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential libssl-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (needed for pydantic-core and liboqs native build)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Create app directory
WORKDIR /app

# Copy your repo files into the container
COPY . .

# Upgrade pip, setuptools, wheel
RUN pip install --upgrade pip setuptools wheel

# Install Python dependencies from requirements.txt
RUN pip install -r requirements.txt

# Clone liboqs and liboqs-python, build and install liboqs-python
RUN git clone https://github.com/open-quantum-safe/liboqs.git && \
    git clone https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && pip install . && cd ..

# Expose port for FastAPI
EXPOSE 8000

# Run uvicorn with your API app
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
