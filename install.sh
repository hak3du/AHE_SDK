#!/bin/bash
echo "🚀 Setting up AHE SDK environment..."
python3 -m venv ahe_env
source ahe_env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "✅ Installation complete. To activate: source ahe_env/bin/activate"
