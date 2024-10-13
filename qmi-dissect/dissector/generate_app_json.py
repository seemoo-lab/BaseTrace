import argparse
import json
import re
import sys
from pathlib import Path

from qmi_services import iphone_services
from qmi_structures import QMIService, LibQMIJson


class AppDefinitions:
    """
    A class used to generate the QMI definition files used by the CellGuard app
    based on the provided of the libqmi data JSON files.
    """

    build_dir: Path
    data_dir: Path
    data_ios_dir: Path
    services: list[QMIService]

    def __init__(self, build_dir: Path, data_dir: Path, data_ios_dir: Path, services: list[QMIService]) -> None:
        self.build_dir = build_dir
        self.data_dir = data_dir
        self.data_ios_dir = data_ios_dir
        self.services = services

    def setup_build_dir(self) -> Path:
        """ Ensure that the build directory exists. """
        if not self.build_dir.exists():
            self.build_dir.mkdir()
        return self.build_dir

    def generate(self) -> Path:
        """ Generate a JSON definition file based on the class properties and return its location. """
        self.setup_build_dir()

        json_service_list = []

        services_name_map = {s.short_name: s for s in self.services}
        data_files = LibQMIJson.read_data_files([self.data_dir, self.data_ios_dir])

        # Iterate through all data files provided by libqmi
        for file_name, file_texts in data_files.items():
            # The file's name must match a given pattern
            match = re.match("qmi-service-(\\w+)\\.json", file_name)
            if not match:
                continue

            # Its service must be known to our application
            service: QMIService = services_name_map.get(match.group(1))
            if not service:
                print(f"Excluded libqmi service {match.group(1)} because it is not in self.services")
                continue

            # We collect all message and indication data present in them
            messages = []
            indications = []

            # For that, we iterate through all top-level elements defined in the file
            for element in LibQMIJson.read_json_data(file_name, file_texts):
                if not element.type or not element.name:
                    continue

                # For now, we only store the numeric identifier and the name of messages and indications
                if element.type == "Message":
                    messages.append({
                        'identifier': int(element.id, 16),
                        'name': element.name
                    })
                elif element.type == "Indication":
                    indications.append({
                        'identifier': int(element.id, 16),
                        'name': element.name
                    })

            # We put all data for the service into a list, that is written into a JSON file
            json_service_list.append({
                'identifier': service.identifier,
                'short_name': service.short_name,
                'long_name': service.long_name,
                'messages': messages,
                'indications': indications
            })

        output_path = self.build_dir.joinpath('qmi-definitions.json')
        with open(output_path, "w") as output_file:
            json.dump(json_service_list, output_file)

        print(f'Collected {len(json_service_list)} QMI services')

        return output_path


def main():
    """ The main function composing all the work. """
    parser = argparse.ArgumentParser(
        prog="generate_lua.py",
        description="Generate a Wireshark Dissector based on the class properties and return its location"
    )
    parser.add_argument(
        '--libqmi-data',
        type=Path,
        default=Path(__file__).parent / "libqmi" / "data",
        help='Path to libqmi data files'
    )
    parser.add_argument(
        '--libqmi-ios-extension',
        type=Path,
        default=Path(__file__).parent.parent.parent / "libqmi-ios-ext",
        help='Path to libqmi iOS extension data files'
    )
    args = parser.parse_args()

    build_dir = Path(__file__).parent / "build"
    data_dir = Path(args.libqmi_data)
    data_ios_dir = Path(args.libqmi_ios_extension)

    if not data_dir.is_dir():
        sys.stderr.write("Specified libqmi data directory does not exists or is not a directory!\n")
        sys.exit(1)

    if not data_ios_dir.is_dir():
        sys.stderr.write("Specified libqmi iOS extension data directory does not exists or is not a directory!\n")
        sys.exit(1)

    definitions = AppDefinitions(build_dir, data_dir, data_ios_dir, iphone_services)
    output_path = definitions.generate()

    print(f"Successfully generated CellGuard JSON definition file {output_path.name}")


if __name__ == "__main__":
    main()
