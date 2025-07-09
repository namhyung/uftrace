#!/bin/bash
set -e
sudo touch /usr/local/bin/uftrace
sudo rm /usr/local/bin/uftrace
sudo make clean
sudo make  DEBUG=1 -j
sudo make install
echo "installed successfully"
