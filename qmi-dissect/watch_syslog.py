#!/usr/bin/env python3

# Watch and capture QMI packets from the running idevicesyslog
# You need to have permissions for executing the dumpcap (you have to be part of the "wireshark" group or run this as sudo)
# Inspired / parts from https://github.com/seemoo-lab/aristoteles/blob/master/tools/watch_frida.py (MIT License)

import argparse
import io
import os
import re
import subprocess

from wireshark import Wireshark
from shutil import which


class WatchSyslog(Wireshark):
    """ Inspect QMI packets in Wireshark extracted using the idevicesyslog utility. """

    def __init__(self, verbose: bool):
        super().__init__(verbose)
        self.syslog_process = None

    def _spawn_device_syslog(self) -> bool:
        if which("idevicesyslog") is None:
            print("idevicesyslog not found!")
            return False

        DEVNULL = open(os.devnull, "wb")

        self.syslog_process = subprocess.Popen(
            "idevicesyslog",
            stdout=subprocess.PIPE,
            stderr=DEVNULL,
        )

        return True

    def check_input_monitor(self) -> bool:
        if self.syslog_process.poll() == 0:
            print("_pollTimer: Syslog has terminated")
            self.syslog_process = None
            return False
        else:
            return True

    def start_input_monitor(self) -> bool:
        if self.syslog_process is None:
            if not self._spawn_device_syslog():
                print("Unable to start Syslog")
                return False

        for line in io.TextIOWrapper(self.syslog_process.stdout, encoding="utf-8"):
            bin_content = re.search(r".*CommCenter.*Bin=\['(.*)']", line)
            if bin_content is not None:
                self.feed_wireshark(bin_content.group(1).lower().replace(" ", ""))

        return True

    def kill_input_monitor(self) -> None:
        if self.syslog_process is not None:
            print("Killing Syslog process...")
            try:
                self.syslog_process.terminate()
                self.syslog_process.wait()
            except OSError:
                print("Error during syslog process termination")
            self.syslog_process = None


# Call script
if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        description="Attaches to the idevicesyslog and pipes the output to wireshark for live monitoring.")
    arg_parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose logs')
    args = arg_parser.parse_args()

    watcher = WatchSyslog(args.verbose)

    watcher.start_monitor()
