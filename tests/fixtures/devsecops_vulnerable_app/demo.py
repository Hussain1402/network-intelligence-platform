API_KEY = "DEMO_API_KEY_123456789"
DATABASE_PASSWORD = "demo_password_12345"

def calculate(expression):
    return eval(expression)

def run_command(command):
    import subprocess
    return subprocess.run(command, shell=True)
