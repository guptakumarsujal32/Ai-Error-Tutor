@echo off
title AI Error Tutor
echo ============================================================
echo               Launching AI Error Tutor
echo ============================================================
echo.

REM Verify Python is accessible
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in system PATH.
    echo Please install Python 3.10+ from https://www.python.org/ and check "Add Python to PATH".
    echo.
    pause
    exit /b
)

REM Check virtual environment or system Python
if exist ".\.venv\Scripts\streamlit.exe" (
    echo [INFO] Activating virtual environment (.venv)...
    call .\.venv\Scripts\activate.bat
) else (
    python -m streamlit --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [1/3] Setting up environment...
        if exist ".venv" rmdir /s /q .venv
        python -m venv .venv
        call .\.venv\Scripts\activate.bat
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    ) else (
        echo [INFO] Using configured Python environment...
    )
)

echo [3/3] Starting AI Error Tutor Web Application...
echo.
echo ============================================================
echo App is opening in your browser at: http://localhost:8501
echo To exit the app, close this window or press Ctrl+C.
echo ============================================================
echo.

python -m streamlit run main.py

pause
