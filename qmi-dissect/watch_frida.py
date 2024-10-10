#!/usr/bin/env python3

# Watch and capture QMI packets by intercepting the packets with frida
# You need to have permissions for executing the dumpcap (you have to be part of the "wireshark" group or run this as sudo)
# Inspired / parts from https://github.com/seemoo-lab/aristoteles/blob/master/tools/watch_frida.py (MIT License)

import argparse
from pathlib import Path

import frida

from wireshark import Wireshark


class WatchFrida(Wireshark):
    """ Inspect QMI packets in Wireshark extracted using Frida. """

    def __init__(self, verbose: bool, direction_bit: bool):
        super().__init__(verbose)
        self.frida_script = None
        self.direction_bit = direction_bit

    def _spawn_frida_script(self):
        frida_session = frida.get_usb_device(1).attach("CommCenter")

        frida_script_file = Path('_agent.js')
        if not frida_script_file.exists():
            print("Please compile the agent using 'npm run build'")
            return False

        self.frida_script = frida_session.create_script(frida_script_file.read_text())
        self.frida_script.load()

        print("  * Initialized functions with Frida.")

        return True

    def on_msg(self, message, data):
        if message['type'] == 'send':
            # Baseband --QMI-> iPhone's application processor
            if message['payload'] == 'qmi_read':
                # If enabled, use the first byte to track the source of the message
                if self.direction_bit:
                    data = b'\x00' + data
                hex_str = data.hex()
                self.feed_wireshark(hex_str)
                if self.verbose:
                    print("incoming qmi read message:")
                    print(hex_str)
            # iPhone's application processor --QMI-> Baseband
            if message['payload'] == 'qmi_send':
                # If enabled, use the first byte to track the source of the message
                if self.direction_bit:
                    data = b'\x01' + data
                hex_str = data.hex()
                self.feed_wireshark(hex_str)
                if self.verbose:
                    print('incoming qmi send message:')
                    print(hex_str)

    def start_input_monitor(self) -> bool:
        if self.frida_script is None:
            if not self._spawn_frida_script():
                print("Unable to initialize Frida script")
                return False

        self.frida_script.on('message', self.on_msg)
        return True

    def check_input_monitor(self) -> bool:
        if self.frida_script.is_destroyed:
            # Script is destroyed
            print("_pollTimer: Frida script has been destroyed")
            self.frida_script = None
            return False
        else:
            return True

    def kill_input_monitor(self):
        if self.frida_script is not None:
            print("Killing Frida script...")
            self.frida_script.unload()
            self.frida_script = None

    def kill_monitor(self):
        super().kill_monitor()
        if self.frida_script is not None:
            print("Killing Frida script...")
            self.frida_script.unload()
            self.frida_script = None


# Call script
if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        description="Intercepts QMI messages using frida and pipes the output to wireshark for live monitoring.")
    arg_parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose logs')
    arg_parser.add_argument(
        '--directionbit',
        action='store_true',
        help='Add a direction bit to the packets sent to Wireshark. '
             'Warning: Requires a special build of the Wireshark dissector.'
    )
    args = arg_parser.parse_args()

    watcher = WatchFrida(args.verbose, args.directionbit)

    watcher.start_monitor()
