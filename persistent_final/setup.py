
import os
import sys
import argparse
import subprocess

def run_command(command, description=None):
    """
    Run a shell command and handle errors
    
    Args:
        command (list): Command and arguments as a list
        description (str, optional): Description of the command for output
    
    Returns:
        bool: True if command succeeded, False otherwise
    """
    if description:
        print(f"\n[SETUP] {description}")
        
    try:
        result = subprocess.run(command, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return False
    except FileNotFoundError as e:
        print(f"Command not found: {e}")
        return False

def check_dependencies():
    """Check if required Python packages are installed"""
    print("[SETUP] Checking dependencies...")
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
        print("Error: Python 3.6 or higher is required.")
        return False
        
    # Check for pip
    if not run_command(["pip", "--version"], "Checking pip"):
        print("Error: pip is not installed or not in PATH.")
        return False
        
    return True

def install_dependencies():
    """Install required Python packages"""
    packages = [
        "grpcio>=1.70.0",
        "grpcio-tools>=1.70.0",
        "protobuf>=5.20.0"
    ]
    
    print(f"[SETUP] Installing dependencies: {', '.join(packages)}")
    
    if not run_command(["pip", "install"] + packages, "Installing packages"):
        print("Error: Failed to install dependencies.")
        return False
        
    return True

def generate_proto():
    """Generate Python code from the protobuf definitions"""
    print("[SETUP] Generating code from protobuf definitions...")
    
    # Generate Python code from .proto file
    proto_file = "./protos/message_service.proto"
    if not os.path.exists(proto_file):
        print(f"Error: Proto file not found: {proto_file}")
        print("Make sure the proto file is located at: ./protos/message_service.proto")
        return False
        
    if not run_command([
        "python", "-m", "grpc_tools.protoc",
        "-I./protos", 
        f"--python_out=./",
        f"--grpc_python_out=./",
        "message_service.proto"
    ], "Generating Python code from proto file"):
        print("Error: Failed to generate Python code from proto file.")
        return False
        
    print("[SETUP] Successfully generated Python code from proto file.")
    return True

def setup():
    """Run the complete setup process"""
    if not check_dependencies():
        return False
        
    if not install_dependencies():
        return False
        
    if not generate_proto():
        return False
        
    print("\n[SETUP] Setup completed successfully!")
    
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Setup the gRPC Chat Application")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    args = parser.parse_args()
    
    if args.skip_deps:
        if not check_dependencies() or not generate_proto():
            sys.exit(1)
    else:
        if not setup():
            sys.exit(1)