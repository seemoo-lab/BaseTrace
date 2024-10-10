import argparse
import random
import time
from datetime import datetime
from pathlib import Path

import simplekml

import lib.apple_location_service as als


def main():
    parser = argparse.ArgumentParser(
        prog='./als_cli.py',
        description='Command line interface for Apple\'s Location Service'
    )
    parser.add_argument(
        'technology', help='Cell Technology', type=str, choices=['gsm', 'scdma', 'umts', 'lte', 'nr', 'cdma'])
    parser.add_argument(
        'country', help='Mobile Country Code (MCC)', type=int)
    parser.add_argument(
        'network', help='Mobile Network Code (MNC) / System Identification (SID) ', type=int)
    parser.add_argument(
        'area', help='Tracking Area Code (TAC) / Location Area Code (LAC) / Network Identification (NID)', type=int)
    parser.add_argument(
        'cell', help='Cell ID / Basestation Identification (BSID)', type=int)

    parser.add_argument(
        '-kml', '--export-kml', type=Path, help='Export results into a KML file.')
    parser.add_argument(
        '-w', '--watch', action='store_true', help='Constantly request the cell (every 5 minutes).')

    args = parser.parse_args()

    if args.watch:
        while True:
            print(f"== {datetime.today()} ==")
            try:
                request(args)
            except Exception as e:
                print(f"Request failed: {e}")
            print()
            time.sleep(5 * 60 + random.randint(0, 15))
    else:
        request(args)


def request(args):
    technology = args.technology
    if technology == 'umts':
        technology = 'gsm'

    request_cell = als.ALSCell(
        technology=als.ALSTechnology[technology.upper()],
        country=args.country,
        network=args.network,
        cell=args.cell,
        area=args.area,
        location=None
    )

    print(f'Requesting cell: {request_cell}')

    response_cells = als.AppleLocationService().request_cells(request_cell)

    print(f'Got {len(response_cells)} cells:')
    for cell in response_cells:
        print(cell)

    kml_path = args.export_kml
    if kml_path:
        if len(response_cells) > 0 and response_cells[0].is_valid():
            kml = simplekml.Kml()
            kml.document.name = "ALS Cells Export"
            kml.document.description = f"Date: {datetime.today()}\n" \
                                       f"Request Cell: {request_cell}"
            for cell in response_cells:
                cell.to_kml_point(kml)
            kml.save(kml_path)
            print(f'Created KML file {kml_path}')
        else:
            print(f'Did not export KML file as there were no cells or the first cell wasn\'t valid.')


if __name__ == '__main__':
    main()
