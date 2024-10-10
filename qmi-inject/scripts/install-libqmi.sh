#!/bin/bash

LIBQRTR_VERSION="qrtr-1-2"
LIBQMI_VERSION="1.33.3"

# Install all required dependencies
sudo apt-get install meson python3 python3-setuptools python-is-python3 \
    libglib2.0-dev libglib2.0-dev libgudev-1.0-dev libmbim-glib-dev \
    libgirepository1.0-dev gtk-doc-tools help2man

# Install libqrtr-glib
git clone https://gitlab.freedesktop.org/mobile-broadband/libqrtr-glib.git
cd libqrtr-glib
git checkout $(LIBQRTR_VERSION)
meson setup build --prefix=/usr
ninja -C build
sudo ninja -C build install
cd ..

# Install libqmi
git clone https://gitlab.freedesktop.org/mobile-broadband/libqmi
cd libqmi
git checkout $(LIBQMI_VERSION)
meson setup build --prefix=/usr
ninja -C build
sudo ninja -C build install
cd ..

echo "libqmi installed successfully"