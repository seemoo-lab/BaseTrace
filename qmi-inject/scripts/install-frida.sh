#!/bin/bash

FRIDA_VERSION="16.0.11"

# Install python3 & pip
sudo apt-get install python3 python3-pip
# Install Python requirements for Frida
pip install colorama prompt-toolkit pygments

# Clone the Frida git repository
git clone --recurse-submodules https://github.com/frida/frida.git
# Go to the directory
cd frida/
# Checkout the wanted Frida version
git checkout $FRIDA_VERSION
# Update all git submodules
git submodule update --recursive

# Build frida & its tools & Python bindings 
make tools-linux-arm64

# Add Frida tools to the $PATH
echo "PATH=\"$(pwd)/build/frida-linux-arm64/bin:\$PATH"\" > ~/.profile
# Add Frida Python bindings to the local installation
echo "$(pwd)/build/frida-linux-arm64/lib/python3.9/site-packages" > ~/.local/lib/python3.9/site-packages/frida.pth

# Exit the build directory
cd ..

echo "Frida installed successfully"
echo "Restart your shell to access the Frida tools"