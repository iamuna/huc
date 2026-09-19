@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [HUC] Creating virtual environment...
  py -3 -m venv .venv || goto :error
)
call .venv\Scripts\activate.bat
python -m pip install -q -r requirements.txt || goto :error
python -m huc
exit /b 0
:error
echo.
echo [HUC] Startup failed. Make sure Python 3.11+ is installed.
pause
exit /b 1
