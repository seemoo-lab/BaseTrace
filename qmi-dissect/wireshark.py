import os
import struct
import subprocess
import time
from threading import Timer
from typing import Optional


class Wireshark:
    """ An abstract class allowing to send binary packets to a Wireshark instance. """

    def __init__(self, verbose: bool):
        """
        Initialize the Wireshark class.

        @param verbose: whether verbose messages should be logged
        """
        self.running = False
        self.wireshark_process = None
        self.poll_timer = None
        self.pcap_data_link_type = 147  # Is DLT_USER_0
        self.start_time = time.time()
        self.verbose = verbose

    def _spawn_wireshark(self) -> bool:
        """
        Initializes the pipe to Wireshark and starts it

        @return: whether Wireshark could be started
        """
        # Global Header Values
        # https://wiki.wireshark.org/Development/LibpcapFileFormat
        PCAP_GLOBAL_HEADER_FMT = "@ I H H i I I I "
        PCAP_MAGICAL_NUMBER = 2712847316
        PCAP_MJ_VERN_NUMBER = 2
        PCAP_MI_VERN_NUMBER = 4
        PCAP_LOCAL_CORECTIN = 0
        PCAP_ACCUR_TIMSTAMP = 0
        PCAP_MAX_LENGTH_CAP = 65535
        PCAP_DATA_LINK_TYPE = self.pcap_data_link_type

        pcap_header = struct.pack(
            PCAP_GLOBAL_HEADER_FMT,
            PCAP_MAGICAL_NUMBER,
            PCAP_MJ_VERN_NUMBER,
            PCAP_MI_VERN_NUMBER,
            PCAP_LOCAL_CORECTIN,
            PCAP_ACCUR_TIMSTAMP,
            PCAP_MAX_LENGTH_CAP,
            PCAP_DATA_LINK_TYPE,
        )

        DEVNULL = open(os.devnull, "wb")

        # Check if wireshark or wireshark-gtk is installed. If both are
        # present, default to wireshark.
        if os.path.isfile("/usr/bin/wireshark"):
            wireshark_binary = "wireshark"
        elif os.path.isfile("/usr/bin/wireshark-gtk"):
            wireshark_binary = "wireshark-gtk"
        elif os.path.isfile("/Applications/Wireshark.app/Contents/MacOS/Wireshark"):
            wireshark_binary = "/Applications/Wireshark.app/Contents/MacOS/Wireshark"
        else:
            print("Wireshark not found!")
            return False

        self.wireshark_process = subprocess.Popen(
            [wireshark_binary, "-k", "-i", "-"],
            stdin=subprocess.PIPE,
            stderr=DEVNULL,
        )
        self.wireshark_process.stdin.write(pcap_header)

        self.poll_timer = Timer(3, self._poll_timer, ())
        self.poll_timer.start()
        return True

    def _poll_timer(self) -> None:
        """
        A timer to check whether all processes are functioning as expected.
        If not, everything is terminated.

        @return: nothing
        """
        if self.running and self.wireshark_process is not None:
            if self.wireshark_process.poll() == 0:
                # Process has ended
                print("_pollTimer: Wireshark has terminated")
                self.kill_monitor()
                self.wireshark_process = None
            elif not self.check_input_monitor():
                self.kill_monitor()
            else:
                # schedule new timer
                self.poll_timer = Timer(3, self._poll_timer, ())
                self.poll_timer.start()

    def check_input_monitor(self) -> bool:
        """
        An abstract method to check whether input monitor is still running properly.

        @return: whether the input monitor is still running properly
        """
        return False

    def start_monitor(self) -> bool:
        """
        Starts the monitor

        @return:
        """
        if self.running:
            print("Monitor already running!")
            return False

        if self.wireshark_process is None:
            if not self._spawn_wireshark():
                print("Unable to start Wireshark.")
                return False

        if not self.start_input_monitor():
            return False

        self.running = True

        print("Monitor started.")

        return True

    def start_input_monitor(self) -> bool:
        """
        An abstract method to start the input monitor.

        @return: whether the start of the input monitor was successful
        """
        return True

    def feed_wireshark(self, data: str | bytes, packet_time: Optional[float] = None) -> None:
        """
        Sends packet data encoding as a hex string to Wireshark.

        @param data: the data of the packet encoded as a hex string
        @param packet_time: a UNIX timestamp indicating when the QMI packet was received, defaults to now
        @return: nothing
        """
        if not packet_time:
            packet_time = time.time()

        packet = bytes.fromhex(data) if type(data) == str else data
        length = len(packet)
        ts_sec = int(packet_time)
        ts_usec = int((packet_time % 1) * 1_000_000)
        pcap_packet = (
                struct.pack("@ I I I I", ts_sec, ts_usec, length, length) + packet
        )
        try:
            self.wireshark_process.stdin.write(pcap_packet)
            self.wireshark_process.stdin.flush()
        except IOError as e:
            print("Monitor: broken pipe. terminate." f"{e}")
            self.kill_monitor()

    def kill_monitor(self) -> None:
        """
        Kills the active monitor and terminates all associated processes.

        @return: nothing
        """
        if self.running:
            self.running = False
            print("Monitor stopped.")
        if self.poll_timer is not None:
            self.poll_timer.cancel()
            self.poll_timer = None
        if self.wireshark_process is not None:
            print("Killing Wireshark process...")
            try:
                self.wireshark_process.terminate()
                self.wireshark_process.wait()
            except OSError:
                print("Error during wireshark process termination")
            self.wireshark_process = None
        self.kill_input_monitor()

    def kill_input_monitor(self) -> None:
        """
        An abstract method to kill the input monitor and clean up everything.

        @return: nothing
        """
        pass
