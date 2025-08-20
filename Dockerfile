# Use a lightweight Python 3.11 base image
FROM python:3.11-slim

# Install system dependencies including git, build tools, and cmake
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential gcc libssl-dev pkg-config curl ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/*

# Install Rust for building native extensions if needed
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy repo files
COPY . .

# Upgrade pip and install Python dependencies including Gunicorn
RUN pip install --upgrade pip setuptools wheel
RUN pip install -r requirements.txt
RUN pip install gunicorn liboqs-python  # prebuilt wheel avoids compiling

# Expose port for Railway
ENV PORT=8000
EXPOSE 8000

# Use Gunicorn to serve Flask API
CMD ["sh", "-c", "gunicorn main:app --bind 0.0.0.0:$PORT"]
