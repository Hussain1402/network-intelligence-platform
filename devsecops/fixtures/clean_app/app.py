def calculate_total(values):
    """Return the sum of a sequence of numeric values."""
    return sum(values)


def format_message(name):
    """Build a simple greeting."""
    return f"Hello, {name}!"


if __name__ == "__main__":
    numbers = [10, 20, 30]
    print(calculate_total(numbers))
    print(format_message("Developer"))
