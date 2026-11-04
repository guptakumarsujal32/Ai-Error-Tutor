#!/bin/bash
echo "============================================================"
echo "              Launching AI Error Tutor"
echo "============================================================"
echo ""

# Check python
if ! command -v python3 &> /dev/null
then
    echo "[ERROR] python3 could not be found. Please install Python 3.10+."
    exit 1
fi

# Setup venv if missing
if [ ! -d ".venv" ]; then
    echo "[1/3] Creating virtual environment (.venv)..."
    python3 -m venv .venv
    source .venv/bin/activate
    echo "[2/3] Installing dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "[INFO] Activating virtual environment..."
    source .venv/bin/activate
fi

echo "[3/3] Starting Streamlit Web Application..."
echo "App is opening at http://localhost:8501"
echo ""
python3 -m streamlit run main.py
