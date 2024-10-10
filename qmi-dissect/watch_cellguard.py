#!/usr/bin/env python3

# Watch and capture QMI packets from a .cells2 file exported by the CellGuard iOS app
# Inspired / parts from https://github.com/seemoo-lab/aristoteles/blob/master/tools/watch_frida.py (MIT License)

import argparse
import base64
from datetime import datetime
import tempfile
import zipfile
from enum import Enum
from pathlib import Path
from typing import Optional

import pandas as pd
from tqdm import tqdm

from wireshark import Wireshark


class Protocol(Enum):
    QMI = "QMI"
    ARI = "ARI"


class WatchCellGuard(Wireshark):
    """ Inspect QMI packets in Wireshark extracted from a CellGuard export file. """

    def __init__(self, verbose: bool, file: Path, start: Optional[int], end: Optional[int], protocols: [Protocol]):
        super().__init__(verbose)
        self.read_completed = False
        self.file_path = file.absolute()
        self.parameter_start = datetime.fromtimestamp(start) if start else None
        self.parameter_end = datetime.fromtimestamp(end) if end else None
        self.protocols = [p.value for p in protocols]

    def start_input_monitor(self) -> bool:
        if self.read_completed:
            print(f"Input was already read")
            return True

        print(f"Reading QMI packets from the CellGuard export...")

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Extract packets.csv from cells2 archive
            with zipfile.ZipFile(self.file_path) as zf:
                try:
                    packets_in_zip = zf.getinfo('packets.csv')
                except KeyError:
                    print(f'The CellGuard export contains no packets.csv!')
                    return False

                packets_csv_path = Path(zf.extract(packets_in_zip, tmp_dir))
                print(f"Extracted packets.csv to {packets_csv_path}")

            # Read packets from packet.csv
            df: pd.DataFrame = pd.read_csv(packets_csv_path, header=0, index_col=False)

            df['collected'] = pd.to_datetime(df['collected'], unit='s')

            # Filter packets
            df = df.loc[df['proto'].isin(self.protocols)]

            if self.parameter_start:
                df = df.loc[df['collected'] >= self.parameter_start]

            if self.parameter_end:
                df = df.loc[df['collected'] <= self.parameter_end]

            # Check if the export contains any QMI packets
            packet_count = len(df.index)
            if packet_count == 0:
                print(f'The CellGuard export contains no {self.protocols} packets (within the selected parameters)!')
                return False

            # Sort by timestamp
            df.sort_values(by=['collected'], inplace=True)

            # Get start & end time
            start_time = df['collected'].iloc[1]
            end_time = df['collected'].iloc[-1]
            self.start_time = start_time.timestamp()

            print(f'First packet: {start_time} UTC')
            print(f'Last packet: {end_time} UTC')

            for packet in tqdm(df.itertuples(index=False), total=packet_count):
                # noinspection PyUnresolvedReferences
                data = base64.decodebytes(bytes(packet.data, 'utf-8'))
                # noinspection PyUnresolvedReferences
                collected = packet.collected
                self.feed_wireshark(data, collected.timestamp())

        self.read_completed = True
        print(f"{packet_count} QMI packets have been successfully imported into Wireshark.")
        return True

    def check_input_monitor(self) -> bool:
        return True


def main():
    arg_parser = argparse.ArgumentParser(
        description='Reads a .cells2 file exported by CellGuard iOS app '
                    'and redirects the binary QMI packets to Wireshark.')
    arg_parser.add_argument('-f', '--file', required=True, type=Path, help='The cells file to process')
    arg_parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose logs')

    arg_parser.add_argument('-qmi', '--qmi', action='store_true', help='Only import QMI packets')
    arg_parser.add_argument('-ari', '--ari', action='store_true', help='Only import ARI packets')

    arg_parser.add_argument('--start', type=int, help='Only process packets younger than the given UNIX timestamp.')
    arg_parser.add_argument('--end', type=int, help='Only process packets older than the given UNIX timestamp.')

    args = arg_parser.parse_args()

    file_path: Path = args.file
    if not file_path.is_file():
        print('No file is present at the given path!')
        exit(1)

    if file_path.suffix != '.cells2':
        print('The given file is not a CellGuard export JSON file as it has the wrong file extension!')
        exit(1)

    if args.start and args.end and args.start > args.end:
        print('The start timestamp may not be larger than the end timestamp.')
        exit(1)

    protocols = []
    if args.qmi:
        protocols.append(Protocol.QMI)
    if args.ari:
        protocols.append(Protocol.ARI)

    # If nothing is selected, use both protocols
    if len(protocols) == 0:
        protocols.append(Protocol.QMI)
        protocols.append(Protocol.ARI)

    watcher = WatchCellGuard(args.verbose, file_path, args.start, args.end, protocols)
    watcher.start_monitor()


# Call script
if __name__ == "__main__":
    main()
