import subprocess
import sys
import os

# Tente usar importlib.metadata (Python 3.8+), caso contrário, use pkg_resources
try:
    from importlib.metadata import distributions
    def get_installed_packages():
        return {dist.metadata['Name'].lower() for dist in distributions()}
except ImportError:
    import pkg_resources
    def get_installed_packages():
        return {pkg.key for pkg in pkg_resources.working_set}

def check_dependencies():
    """
    Verifica quais dependências já estão instaladas.
    """
    required = get_required_packages()
    installed = get_installed_packages()
    missing = required - installed
    
    return missing

def get_required_packages():
    """
    Obtém a lista de pacotes necessários do requirements.txt
    """
    required = set()
    try:
        with open('requirements.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    required.add(line.split('==')[0].lower())
    except FileNotFoundError:
        print("File requirements.txt not found.")
    
    return required

def install_requirements():
    """
    Install the dependencies listed in the requirements.txt file.
    """
    print("Checking for required dependencies...")
    
    missing = check_dependencies()
    
    if not missing:
        print("All dependencies are already installed.")
        return

    print(f"Installing missing dependencies: {', '.join(missing)}")

    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("All dependencies were installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}", file=sys.stderr)
        sys.exit(1)

def check_python_version():
    """
    Verifica se a versão do Python é compatível.
    """
    required_version = (3, 6)
    current_version = sys.version_info[:2]
    
    if current_version < required_version:
        print(f"Python version is incompatible. Requires Python {required_version[0]}.{required_version[1]} or higher.")
        print(f"Current version: {current_version[0]}.{current_version[1]}")
        sys.exit(1)

if __name__ == "__main__":
    print("SafeAnon 2.0 - Dependency Setup")
    print("-" * 50)
    
    check_python_version()
    install_requirements()

    print("Setup complete. The system is ready for use.")