"""
Test Suite - Performance benchmarking with real-world samples
"""

import os
import sys
import time
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pipeline import AIErrorTutor

# 20+ Real-world test samples
TEST_SAMPLES = [
    {
        "name": "Missing print function",
        "code": "prnt('Hello World')",
        "expected_error": "NameError"
    },
    {
        "name": "String + Integer",
        "code": "age = 25\nprint('Age: ' + age)",
        "expected_error": "TypeError"
    },
    {
        "name": "Missing colon in function",
        "code": "def greet(name)\n    print(name)",
        "expected_error": "SyntaxError"
    },
    {
        "name": "List index out of range",
        "code": "items = [1, 2, 3]\nprint(items[10])",
        "expected_error": "IndexError"
    },
    {
        "name": "Dictionary missing key",
        "code": "person = {'name': 'John'}\nprint(person['age'])",
        "expected_error": "KeyError"
    },
    {
        "name": "Division by zero",
        "code": "result = 100 / 0",
        "expected_error": "ZeroDivisionError"
    },
    {
        "name": "Invalid int conversion",
        "code": "num = int('hello')",
        "expected_error": "ValueError"
    },
    {
        "name": "Wrong method name (append vs push)",
        "code": "lst = []\nlst.push(5)",
        "expected_error": "AttributeError"
    },
    {
        "name": "Import non-existent module",
        "code": "import nonexistent_module_xyz",
        "expected_error": "ModuleNotFoundError"
    },
    {
        "name": "Unmatched parenthesis",
        "code": "print('Hello'",
        "expected_error": "SyntaxError"
    },
    {
        "name": "Indentation error",
        "code": "def test():\nprint('hello')",
        "expected_error": "IndentationError"
    },
    {
        "name": "Calling None",
        "code": "x = None\nx()",
        "expected_error": "TypeError"
    },
    {
        "name": "String index out of range",
        "code": "s = 'hi'\nprint(s[10])",
        "expected_error": "IndexError"
    },
    {
        "name": "Using undefined variable",
        "code": "print(undefined_var)",
        "expected_error": "NameError"
    },
    {
        "name": "Wrong argument count",
        "code": "def add(a, b):\n    return a + b\nadd(1)",
        "expected_error": "TypeError"
    },
    {
        "name": "Modifying tuple",
        "code": "t = (1, 2, 3)\nt[0] = 5",
        "expected_error": "TypeError"
    },
    {
        "name": "Invalid slice",
        "code": "lst = [1, 2, 3]\nlst['a':'b']",
        "expected_error": "TypeError"
    },
    {
        "name": "Recursive limit",
        "code": "def recurse():\n    recurse()\nrecurse()",
        "expected_error": "RecursionError"
    },
    {
        "name": "File not found",
        "code": "with open('nonexistent_file_xyz.txt') as f:\n    pass",
        "expected_error": "FileNotFoundError"
    },
    {
        "name": "Unpacking mismatch",
        "code": "a, b, c = [1, 2]",
        "expected_error": "ValueError"
    },
]


def run_benchmark(tutor: AIErrorTutor) -> Dict:
    """Run benchmark tests and collect metrics."""
    results = {
        'total': len(TEST_SAMPLES),
        'passed': 0,
        'failed': 0,
        'times': [],
        'details': []
    }

    for sample in TEST_SAMPLES:
        start_time = time.time()
        result = tutor.analyze_code(sample['code'])
        elapsed = time.time() - start_time

        passed = result.error_type == sample['expected_error']

        results['times'].append(elapsed)
        if passed:
            results['passed'] += 1
        else:
            results['failed'] += 1

        results['details'].append({
            'name': sample['name'],
            'expected': sample['expected_error'],
            'got': result.error_type,
            'passed': passed,
            'time': elapsed,
            'explanation': result.friendly_explanation[: 100] + '.. .'
            if len(result.friendly_explanation) > 100
            else result.friendly_explanation
        })

    results['avg_time'] = sum(results['times']) / len(results['times'])
    results['accuracy'] = results['passed'] / results['total'] * 100

    return results


def print_report(results: Dict):
    """Print formatted benchmark report."""
    print("=" * 70)
    print("  AI ERROR TUTOR - PERFORMANCE BENCHMARK REPORT")
    print("=" * 70)
    print(f"\n[+] Summary:")
    print(f"   Total Tests:      {results['total']}")
    print(f"   Passed:           {results['passed']} [OK]")
    print(f"   Failed:          {results['failed']} [FAIL]")
    print(f"   Accuracy:        {results['accuracy']:.1f}%")
    print(f"   Avg Time:        {results['avg_time'] * 1000:.2f}ms")

    print(f"\n{'=' * 70}")
    print("  Detailed Results:")
    print("-" * 70)

    for detail in results['details']:
        status = "[OK]" if detail['passed'] else "[FAIL]"
        print(f"\n{status} {detail['name']}")
        print(f"   Expected: {detail['expected']}, Got: {detail['got']}")
        print(f"   Time: {detail['time'] * 1000:.2f}ms")
        safe_exp = detail['explanation'].encode('ascii', errors='replace').decode('ascii')
        print(f"   Explanation: {safe_exp}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    print("Initializing AI Error Tutor for benchmarking...")
    tutor = AIErrorTutor(use_ai=True) 

    print("Running benchmark...")
    results = run_benchmark(tutor)
    print_report(results)