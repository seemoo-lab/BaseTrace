import argparse
import binascii
import os
import socket
import time
import frida


def get_argparse():
    parser = argparse.ArgumentParser(
        prog='iphone-qmi-glue',
        description='Connect an iPhone baseband chip via a unix domain socket to libqmi'
    )
    parser.add_argument('-U', '--usb', action='store_true',
                        help='connect to USB device')
    parser.add_argument(
        '-H', '--host', help='connect to remote frida-server on HOST')
    return parser


class IPhoneQMIGlue:

    # Arguments supplied by argparse
    args = None

    # Socket connection
    socket_connection = None

    # Counts the number of received & sent QMI packets
    received = 0
    sent = 0

    # We assume that there are two different QMUX queues
    qmux1 = False

    # Wait for writeAsync parameters to be initialized
    write_state_init = False

    def __init__(self, args) -> None:
        self.args = args

    ### FRIDA ###

    # frida Python package documentation:
    # https://github.com/frida/frida-python/blob/a2643260742285acd5b19da6837e7b08c528d3e9/frida/__init__.py
    # https://github.com/frida/frida-python/blob/a2643260742285acd5b19da6837e7b08c528d3e9/frida/core.py

    def on_message(self, message, data):
        try:
            if message['payload'] == "setup":
                self.write_state_init = True
                return
        except KeyError:
            print("[FRIDA] There's an error in the script, debug it manually!")
            return

        # Manage invalid data and data direction
        if data is None:
            print("[FRIDA] Empty data, did CommCenter crash?")
            return
        # Data starts with 01 in rx direction so we use other magic bytes
        elif data[0] == 0x23:
            # alternative qmux queue, I think there are just two queues
            self.qmux1 = not self.qmux1
            return

        # Relays the received data from the iPhone to libqmi
        if self.socket_connection:
            self.socket_connection.sendall(data)

        self.received += 1

    def connect_to_device(self):
        if self.args.usb:
            return frida.get_device_manager().get_usb_device()
        elif self.args.host:
            # Connects to the FRIDA server on port 27042 running on the device over the network
            # e.g. VM (192.168.64.3) --UTM network--> Mac (192.168.64.1) --iproxy--> iPhone
            return frida.get_device_manager().add_remote_device(self.args.host)
        else:
            get_argparse().print_help()
            print('Specify a target device either with --usb or --host')
            quit(1)

    def load_script(self):
        device = self.connect_to_device()

        # Attaches to the CommCenter process
        frida_session = device.attach("CommCenter")

        # Loads the script to be injected from an external file
        # It uses function-based symbol and works only with Qualcomm chips.
        # The symbols work on an iPhone 12 with iOS 14.2.1
        with open('_agent.js', 'r') as file:
            script_code = file.read()

        script = frida_session.create_script(script_code)
        script.on("message", self.on_message)
        script.load()

        print("[FRIDA] Collecting write state information...")
        # print("[FRIDA] Tip: Unlock your device to collect state information")
        while not self.write_state_init:
            time.sleep(0.1)
        print("[FRIDA] Got all required state information")

        return script

    ### SOCKET ###

    # https://pymotw.com/2/socket/uds.html

    def open_socket(self):
        script = self.load_script()

        socket_address = './qmux_socket'

        # Try to delete an existing socket
        try:
            os.unlink(socket_address)
        except OSError:
            if os.path.exists(socket_address):
                raise

        # Create a UDS sockets
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Bind the socket to the port
        print(f'[Socket] Opening Socket {socket_address}')
        sock.bind(socket_address)

        # Listen for incoming connections
        sock.listen(1)

        while True:
            # Wait for connections
            print('[Socket] Waiting for a connection')
            self.socket_connection, client_address = sock.accept()

            # Accept a connection
            try:
                if client_address == '':
                    client_address = 'unknown'
                print(f'[Socket] Connection from {client_address}')

                while True:
                    data = self.socket_connection.recv(16)

                    if data:
                        # Send QMI packets data back to the phone
                        # Convert binary data to hex strings as it needs to be JSON serializable for FRIDA
                        # print(binascii.hexlify(data).decode('ascii'))
                        script.exports_sync.injectQMI(
                            binascii.hexlify(data).decode('ascii'))
                    else:
                        print('[Socket] No more data from client')
                        break
            finally:
                # Cleanup the connection
                self.socket_connection.close()
                self.socket_connection = None


def main():
    parser = get_argparse()
    glue = IPhoneQMIGlue(parser.parse_args())
    glue.open_socket()


if __name__ == '__main__':
    main()
