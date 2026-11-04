import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
"""Configuration file for AI Error Tutor"""

# Target Python Errors to Handle
TARGET_ERRORS = [
    "SyntaxError",
    "IndentationError",
    "NameError",
    "TypeError",
    "ValueError",
    "IndexError",
    "KeyError",
    "AttributeError",
    "ImportError",
    "ModuleNotFoundError",
    "ZeroDivisionError",
    "FileNotFoundError",
    "UnboundLocalError",
    "RecursionError",
    "StopIteration"
]

