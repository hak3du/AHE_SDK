#!/bin/bash
echo "[INFO] Setting up AHE SDK environment..."

# Create virtual environment
python3 -m venv ahe_env
source ahe_env/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

echo "[INFO] Installation complete! Run './run.sh' to start the API."