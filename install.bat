@echo off
echo [INFO] Setting up AHE SDK environment...

REM Create virtual environment
python -m venv ahe_env

REM Activate and install dependencies
call ahe_env\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

echo [INFO] Installation complete! Run run.bat to start the API.