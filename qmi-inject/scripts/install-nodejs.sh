#!/bin/bash

# Sources: 
# - https://github.com/nodesource/distributions/blob/master/README.md#using-debian-as-root-1
# - https://www.cyberciti.biz/faq/how-to-run-multiple-commands-in-sudo-under-linux-or-unix/
sudo -- bash -c 'curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && apt-get install -y nodejs'
