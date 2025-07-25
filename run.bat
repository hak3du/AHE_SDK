
@echo off
echo ▶ Starting AHE API...
call ahe_env\Scripts\activate
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
pause
