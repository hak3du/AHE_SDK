@echo off
echo 🚀 Setting up AHE SDK environment...
python -m venv ahe_env
call ahe_env\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
echo ✅ Installation complete. To activate: call ahe_env\Scripts\activate
pause
