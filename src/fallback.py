"""Dependency-free explanations used when Gemini is unavailable."""


class FallbackExplainer:
    """Rule-based fallback for common Python errors."""

    EXPLANATIONS = {
        'SyntaxError': "There's a syntax error in your code. Common causes include: missing colons, unmatched parentheses, or incorrect indentation.",
        'NameError': "You're trying to use a variable or function that doesn't exist. Check for typos or make sure it's defined before use.",
        'TypeError': "You're trying to perform an operation with incompatible types. Check if you need to convert types using str(), int(), or float().",
        'IndexError': "You're trying to access an index that doesn't exist in the list. Remember, Python lists start at index 0!",
        'KeyError': "You're trying to access a dictionary key that doesn't exist. Use .get() method or check if the key exists first.",
        'ValueError': "The value you provided isn't valid for this operation. Check that your input matches the expected format.",
        'ZeroDivisionError': "You're trying to divide by zero, which is mathematically undefined. Check that your divisor is not zero.",
        'AttributeError': "You're trying to use a method or property that doesn't exist for this type of object. Check the object type and available methods.",
        'IndentationError': "Your code indentation is inconsistent. Use 4 spaces for each indentation level and make sure all lines in the same block match.",
        'SecurityError': "Your code was blocked because it contains potentially dangerous operations that are not allowed in a learning environment.",
        'TimeoutError': "Your code took too long to execute and was stopped. This usually happens because of an infinite loop (e.g. while condition never becomes False) or endless recursion.",
    }

    def explain(self, error_type: str, error_message: str) -> str:
        """Generate a fallback explanation."""
        return self.EXPLANATIONS.get(
            error_type,
            f"An error occurred: {error_message}. Please review your code carefully."
        )