@echo off
cd /d "%~dp0"
if not exist .deps-installed (
  echo Installing requirements, one time only...
  python -m pip install -q -r requirements.txt && echo ok> .deps-installed
)
if not exist config.toml copy config.example.toml config.toml >nul
if not exist .env copy .env.example .env >nul
python honeypot_main.py %*
if errorlevel 1 pause
