#!/usr/bin/env python3

# Watch and capture QMI packets from a .logarchive file part of a sysdiagnose
# You need to have permissions for executing the dumpcap (you have to be part of the "wireshark" group or run this as sudo)
# Inspired / parts from https://github.com/seemoo-lab/aristoteles/blob/master/tools/watch_frida.py (MIT License)

import argparse
import base64
import csv
import platform
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from tqdm import tqdm

from wireshark import Wireshark


class WatchLogArchiveMacOS(Wireshark):
    """ Inspect QMI packets in Wireshark extracted from a logarchive file. """

    def __init__(self, verbose: bool, file: Path, last: str):
        super().__init__(verbose)
        self.completed_read: Optional[subprocess.CompletedProcess] = None
        self.file = file.absolute()
        self.last = last

    def _read_file(self) -> bool:
        if platform.system() != "Darwin":
            print(".logarchive files can only be read on macOS")
            return False

        log_binary = Path("/usr/bin/log")
        if not log_binary.exists():
            print("log executable not found!")
            return False

        if not self.file.suffix == ".logarchive":
            print(f"{self.file} is not a .logarchive file")
            return False

        if not self.file.is_dir():
            print(f"{self.file} must a directory (although it is shown as a file on macOS)")
            return False

        # We gain significant speedup here by pre-filtering the logs.
        print(f"Using {log_binary} to read the log archive...")

        log_args = [log_binary, "show"]

        if not self.last:
            print("No limit set. Reading the whole archive, this might take a while!")
        else:
            print(f"Limiting logs to the last {self.last}.")
            log_args.append('--last')
            log_args.append(self.last)

        log_args.append('--process')
        log_args.append('CommCenter')
        log_args.append(self.file)

        self.completed_read = subprocess.run(
            log_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )

        if self.completed_read.returncode != 0:
            print(f"Got a non-zero exit code: {self.completed_read.returncode}")

        return True

    def start_input_monitor(self) -> bool:
        if not self.completed_read:
            if not self._read_file():
                print(f"Unable to read the file {self.file}")
                return False

        print("Processing the extracted logs...")
        time_format = "%Y-%m-%d %H:%M:%S.%f%z"
        time_regex = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}(?:[+-]\d{4})?) "
        time_pattern = re.compile(time_regex)
        qmi_pattern = re.compile(time_regex + r".*CommCenter.*Bin=\['(.*)']")

        bytes_out: bytes = self.completed_read.stdout
        string_out = bytes_out.decode("utf-8")

        self.start_time = None
        count = 0

        for line in tqdm(string_out.splitlines(), unit="lines"):
            # Set the start time using the first parseable line
            if self.start_time is None:
                time_match = time_pattern.search(line)
                if time_match is not None:
                    time = datetime.strptime(time_match.group(1), time_format)
                    # Some entries carry invalid dates (~1970) and we want to filter them out
                    if time.year >= 2000:
                        self.start_time = time.timestamp()

            # Check all lines for QMI packet data and if found send it to Wireshark
            qmi_match = qmi_pattern.search(line)
            if qmi_match is not None:
                packet_time = datetime.strptime(qmi_match.group(1), time_format).timestamp()
                hex_qmi_data = qmi_match.group(2).lower().replace(" ", "")
                self.feed_wireshark(hex_qmi_data, packet_time)
                count += 1

        print(f"{count} QMI packets have been successfully imported into Wireshark.")

        return True


class WatchLogArchiveLinux(Wireshark):
    """
    Inspect QMI packets in Wireshark extracted from a logarchive file using the macos-unified logs library.
    """

    unified_parser: Path
    tmp_dir: tempfile.TemporaryDirectory = None
    output_csv: Path = None

    def __init__(self, verbose: bool, file: Path, unified_parser: Path):
        super().__init__(verbose)
        self.file = file.absolute()
        self.unified_parser = unified_parser

    def _parse_file(self) -> bool:
        if not self.unified_parser.exists():
            print("Please compile the unified_parser parser in the 'logarchive' directory using 'rust build --release'!")
            return False

        if not self.file.suffix == ".logarchive":
            print(f"{self.file} is not a .logarchive file")
            return False

        if not self.file.is_dir():
            print(f"{self.file} must a directory (although it is shown as a file on macOS)")
            return False

        # We create a temporary directory for the parser's CSV output
        self.tmp_dir = tempfile.TemporaryDirectory(prefix='watch_logarchive_')
        self.output_csv = Path(self.tmp_dir.name).joinpath('output.csv').absolute()

        print(f'Storing temporary files in {self.tmp_dir}')
        print(f"Using {self.unified_parser.name} to read the log archive... (this might take a while)")

        # We run the parser
        parse_process = subprocess.run(
            [self.unified_parser, '--input', self.file, '--output', self.output_csv],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if parse_process.returncode != 0:
            print(f"Got a non-zero exit code: {parse_process.returncode}")

        return True

    def start_input_monitor(self) -> bool:
        # If we've got no output CSV, we run the parser
        if not self.output_csv:
            if not self._parse_file():
                print(f"Unable to read the file {self.file}")
                self.tmp_dir.cleanup()
                return False

        print("Processing the extracted logs...")

        # Note that time and QMI patterns are a bit different to the other approach
        time_format = "%Y-%m-%dT%H:%M:%S.%f"
        # The time format does not include the timezone in this case,
        # but we'll ignore that as we're only interested in relative timestamps.
        time_pattern = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z")
        qmi_pattern = re.compile(r"QMI.*Bin=\[(.*)]")

        # We first collect all packets as they are not always in correct order
        self.start_time = None
        packets: list[tuple[str, float]] = []
        private_packet_count = 0

        # Read the CSV file we've got from the unified_parser executable
        with open(self.output_csv, 'r', newline='') as csvfile:
            # https://stackoverflow.com/a/39151484
            reader = csv.reader(x.replace('\0', '') for x in csvfile)
            for row in tqdm(reader, unit=' lines'):
                # The first line of the CSV file assigns names to columns
                timestamp = row[0]
                message = row[1]

                # Check if the timestamp and QMI patterns match
                qmi_match = qmi_pattern.search(message)
                if qmi_match is not None:
                    # Extract base64 encoded packet
                    # It is only available if the baseband profile is installed, otherwise we just get <private>
                    packet_b64_str = qmi_match.group(1)
                    if packet_b64_str == '<private>':
                        private_packet_count += 1
                        continue
                    elif packet_b64_str == '<Missing message data>':
                        print(f'Encountered an invalid QMI packet "{message}"')
                        continue
                    # Convert the packet's timestamp (which is an int in microseconds) to seconds
                    packet_time = int(timestamp) / 1_000_000
                    # Store both the data string and the timestamp
                    packets.append((packet_b64_str, packet_time))
                    # Find the smallest start time
                    if self.start_time is None or packet_time < self.start_time:
                        self.start_time = packet_time

        if private_packet_count > 0:
            print(f'Found {private_packet_count} packets with private data. Was the baseband debug profile installed?')

        # Clean the temporary directory
        self.tmp_dir.cleanup()

        # Sort packet list by timestamp
        packets.sort(key=lambda x: x[1])

        # Feed all found QMI packets into Wireshark
        # It's important to do this after the smallest start time has been set
        for packet in packets:
            binary_data = base64.b64decode(packet[0])
            timestamp = packet[1]
            self.feed_wireshark(binary_data, timestamp)

        print(f"{len(packets)} QMI packets have been successfully imported into Wireshark.")
        print("Please be aware, that this approach might pick up "
              "fewer QMI packets compared to the built-in log binary on Mac's.")

        return True


# Validate limit argument
def limit_type(arg_value, pat=re.compile(r"^[0-9]*[mhd]$")):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError("Invalid limit argument!")
    return arg_value


# Call script
if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        description='Reads a .logarchive file from a iOS sysdiagnose '
                    'and redirects the binary QMI packets to Wireshark.')
    arg_parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose logs')
    arg_parser.add_argument('-f', '--file', required=True, type=Path, help='The logarchive file to process')
    arg_parser.add_argument(
        '-l', '--last', type=limit_type,
        help=' <num>[m|h|d] Only parse recent events up to the given limit (faster)')
    arg_parser.add_argument(
        '-p', '--parser', action='store_true',
        help='Use our custom parser adapted from the macos-unifiedlogs project.')
    args = arg_parser.parse_args()

    if platform.system() == "Darwin" and not args.parser:
        # Use the built-in log binary on macOS
        watcher = WatchLogArchiveMacOS(args.verbose, args.file, args.last)
    else:
        # Path to the parser
        unified_parser = (
            Path(__file__).parent.joinpath('logarchive', 'target', 'release', 'unifiedlog_parser').absolute()
        )
        print(unified_parser)

        # Check if the parser already has been compiled
        if not unified_parser.exists():
            print("Please compile the unified_parser parser in the 'logarchive' directory using 'rust build --release'!")
            exit(1)

        # Always use the unifiedlogs parser on non-macOS systems
        watcher = WatchLogArchiveLinux(args.verbose, args.file, unified_parser)

    watcher.start_monitor()
