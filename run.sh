#!/bin/bash
echo "▶ Starting AHE API..."
source ahe_env/bin/activate
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
