import argparse
import re
import sys
from enum import Enum
from pathlib import Path

import pandas as pd

from qmi_services import iphone_services
from qmi_structures import QMIService, LibQMIJson, LibQMIElement


class PacketType(Enum):
    MESSAGE = "Message"
    INDICATION = "Indication"
    COMMAND_DRIVER = "CommandDriver"
    NOT_FOUND = "Manual"


extract_patterns = {
    # libABMCommandDrivers (Apple Baseband Manager)
    r'qmi6Client9SendProxy8callback[A-Z]+\d+(p2p|[A-Za-z]+)(?:\d+abm)?\d+([A-Za-z]+)': PacketType.MESSAGE,
    r'qmi6Client13setIndHandler[A-Z]+\d+(p2p|[A-Za-z]+)(?:\d+abm)\d+(\w+[A-Za-z])\d+Indication': PacketType.INDICATION,
    r'cast_message_type[A-Z]+\d+(p2p|[A-Za-z]+)(?:\d+abm)?\d+([A-Za-z]+)': PacketType.MESSAGE,
    # libCommCenterMCommandDrivers (Main library for QMI processing)
    r'qmi8Response\w+\d(p2p|[a-z]+)\d+(\w+[A-Za-z])\d+Response': PacketType.MESSAGE,
    r'qmi10Indication\w+\d(p2p|[a-z]+)\d+(\w+[A-Za-z])\d+Indication': PacketType.INDICATION,
    # libCommCenterMCommandDrivers (Extracted based on the MutableMessageBase constructor)
    r'([A-Z][A-Za-z2_]+(?:Driver|Manager|Aggregator|ClientIP|Formatter|ContextIP(?:Base)?|Service))E?\d+([A-Za-z_0-9]+[A-Za-z](?:3GPP2)?)(?:E|I)': PacketType.COMMAND_DRIVER,
    # r'__[A-Z]{2}\d{2}([A-Za-z]+)\d+([A-Za-z_]+)E': PacketType.COMMAND_DRIVER,
}

# Idea: Map of CommandDriver to services
# To map classes to QMI service, use Ghidra and navigate to methods calling the MutableMessageBase constructor.
# THere are other methods or structures called which expose the QMI service name:
# - &qmi::MutableMessageBase::TlvWrapper<vs::tlv::HandoverEventEnable>::typeinfo,
# Idea: Create Ghidra plugin to use the this code pattern to annotate methods with QMI services
# -> See TlvWrapper<> class
# Idea: Add extra row to existing Ghidra plugin to export unmangled function names
command_drivers = {
    # QMIDataContextIPv4
    'QMIDataContextIP': 'wds',
    'QMIAttachApnCommandDriver': 'wds',
    'QMIDataSystemDeterminationManager': 'dsd',
    'QMISMSCommandDriver': 'wms',
    'ZN22EurekaC2KCallFormatter': 'vs',
    # STK = SIM Toolkit
    'QMI_STK_CommandDriver': 'cat',
    'QMIPreferredNetworksCommandDriver': 'nas',
    'ZN22EurekaGSMCallFormatter': 'vs',
    'QMIAQMCommandDriver': 'bsp',
    'QMIBasebandSettingsDriver': 'dms',
    'QMICDMASettingsCommandDriver': 'vs',
    'QMIEmbmsCommandDriver': 'nas',
    'QMILegacyAwdCommandDriver': 'awd',
    'QMIAwdCommandDriver': 'awd',
    'AwdCommandDriver': 'awd',
    'QMIATCommandDriver': 'at',
    'QMIDataCommandDriver': 'wds',
    'QMIP2PCommandDriver': 'p2p',
    'QMIAudioCommandDriver': 'audio',
    'QMIWiFiSettingsCommandDriver': 'nas',
    'QMILegacyDataSubscriptionCommandDriver': 'uim',
    # TODO: NAS & DSD
    'QMIDataSubscriptionCommandDriver': 'nas',
    'EurekaCallFormatter': 'vs',
    'QMIEnhancedLQMCommandDriver': 'elqm',
    'QMICellMonitorCommandDriver': 'nas',
    'QMIDormancyCommandDriver': 'wds',
    'DormancyCommandDriver': 'wds',
    'QMIPhonebookCommandDriver': 'pbm',
    'ActivationCommandDriver': 'bsp',
    'PreferredNetworksCommandDriver': 'nas',
    'PreferredNetworksFactoryCommandDriver': 'nas',
    'QMIDownLinkFilterCommandDriver': 'dfs',
    'QMICallAudioDriver': 'audio',
    'QMIDesenseCommandDriver': 'nas',
    'VinylQMICommandDriver': 'vinyl',
    'EurOTASPService': 'vs',
    'EURSimCommandDriver': 'uim',
    'QMIDataContextIPAggregator': 'wds',
    'QMIDataContextIPBase': 'wds',
    'SignalStrengthCommandDriver': 'nas',
    'QMIAudioRoutingCommandDriver': 'audio',
    # TODO: VS & NAS
    'EurekaCallCommandDriver': 'nas',
    'QMINetworkListCommandDriver': 'nas',
    'NetworkListCommandDriver': 'nas',
    'QMIDMSCommandDriver': 'dms',
    'QMIActivationCommandDriver': 'bsp',
    'QMISuppServicesCommandDriver': 'vs',
    'QMINetworkRegistrationDriver': 'nas',
    'QMIQOSClientIP': 'qos',
}


class GhidraImporter:
    data_dir: Path
    data_ios_dir: Path
    services: list[QMIService]
    compiled_patterns: dict[re.Pattern, PacketType]

    def __init__(self, data_dir: Path, data_ios_dir: Path, services: list[QMIService]) -> None:
        self.data_dir = data_dir
        self.data_ios_dir = data_ios_dir
        self.services = services
        self.compile_patterns()

    def compile_patterns(self):
        """ Compiles the regex patterns to allow for a faster processing. """
        self.compiled_patterns = {}
        for pattern, packet_type in extract_patterns.items():
            self.compiled_patterns[re.compile(pattern)] = packet_type

    def convert_to_libqmi(self, ghidra_file: Path) -> int:
        """ Convert a CSV file exported from Ghidra into libqmi data structures used for the dissector. """
        # Read CSV
        df = pd.read_csv(ghidra_file)

        # Parse CSV data with regex
        # Apply a function to generate multiple columns in the data frame: https://stackoverflow.com/a/30027273
        df[['Type', 'Service', 'Name']] = df['Function'].apply(self.extract_with_regex)

        # Convert the message IDs to the hex format of libqmi
        df['Message ID'] = df['Message ID'].apply(lambda msg_id: f'0x{msg_id.rstrip("h").upper()}')

        # Print message IDs that must be handled manually
        write_packet_types = [PacketType.INDICATION, PacketType.MESSAGE]
        manual_df = df[~(df["Type"].isin(write_packet_types))]
        df = df[df['Type'].isin(write_packet_types)]

        if manual_df.shape[0] > 0:
            print('The following message / indication IDs can not be handled automatically. ' +
                  'Please extend this script to support them. \n' +
                  f'{manual_df.to_string()}')

        # Convert the Python enum object into its raw string value to support the upcoming comparison
        df['Type'] = df['Type'].apply(lambda msg_type: msg_type.value)

        # Read JSON & grab the existing service IDs from libqmi and our iOS data
        libqmi_service_ids = self.list_message_ids(self.data_dir)
        ios_service_ids = self.list_message_ids(self.data_ios_dir)
        existing_service_ids = pd.concat([libqmi_service_ids, ios_service_ids], ignore_index=True)

        # Remove the existing message IDs from the dataframe by performing an anti-join
        # See: https://stackoverflow.com/a/55543744
        outer_join = df.merge(existing_service_ids, how='outer', indicator=True)
        anti_join = outer_join[outer_join['_merge'] == 'left_only'].drop('_merge', axis=1)
        df = anti_join

        # Remove duplicates that are caused by multiple entries in the Ghidra CSV file
        df = df.drop_duplicates(subset=['Service', 'Type', 'Message ID'])

        # Write data back to JSON files that based on service names, only if we've got new data
        if df.shape[0] > 0:
            self.write_new_message_ids(self.data_ios_dir, df)

        # Print all services for inspection
        # print(df['Service'].drop_duplicates().to_string())
        # print(df.to_string())

        return df.shape[0]

    def extract_with_regex(self, function: str) -> pd.Series:
        """ Extracts tuples of service, message name, and type from Ghidra CSV files using regular expressions. """
        for pattern, packet_type in self.compiled_patterns.items():
            match = pattern.search(function)
            if match:
                # Add a whitespace before each capital letter: https://stackoverflow.com/a/199075
                service = match.group(1)
                # name = re.sub(r"(\w)([A-Z])", r"\1 \2", match.group(2))
                name = match.group(2)

                if packet_type == PacketType.COMMAND_DRIVER:
                    # Are there command drivers which accept indications? -> Maybe at the register methods
                    packet_type = PacketType.MESSAGE
                    name = f'{service}::{name}'
                    # Fail if the command driver cannot be mapped to a QMI service
                    if service not in command_drivers or command_drivers[service] == '':
                        return pd.Series([PacketType.NOT_FOUND, '', name])
                    service = command_drivers[service]

                # print(f"Extracted: {service} - {name} ({packet_type})")
                return pd.Series([packet_type, service, name])

        # We've got no match
        print(f"Can't extract service & name for '{function}'")
        return pd.Series([PacketType.NOT_FOUND, '', ''])

    @staticmethod
    def list_message_ids(directory: Path) -> pd.DataFrame:
        """
        Reads the libqmi data files from the given directory (not its subdirectories) and returns a
        DataFrame of already existing message IDs.
        """
        records: list[tuple[str, str, str]] = []

        for file_name, file_texts in LibQMIJson.read_data_files([directory], sub_dirs=False).items():
            match = re.match("qmi-service-(\\w+)\\.json", file_name)
            if not match:
                continue

            service = match.group(1)
            for element in LibQMIJson.read_json_data(file_name, file_texts):
                if element.id:
                    records.append((service, element.id, element.type))

        # https://stackoverflow.com/a/42837693
        df = pd.DataFrame.from_records(data=records, columns=['Service', 'Message ID', 'Type'])
        df['Message ID'] = df['Message ID'].apply(lambda msg_id: msg_id)
        return df

    @staticmethod
    def write_new_message_ids(directory: Path, data: pd.DataFrame):
        """ Appends the new messages IDs in the given DataFrame to the files in the given directory. """
        service_elements: dict[str, list[LibQMIElement]] = {}

        # Load all existing service elements from the given folder
        for file_name, file_texts in LibQMIJson.read_data_files([directory], sub_dirs=False).items():
            match = re.match("qmi-service-(\\w+)\\.json", file_name)
            if not match:
                continue

            service_elements[file_name] = LibQMIJson.read_json_data(file_name, file_texts)

        # Add the new service elements from the DataFrame
        for index, row in data.iterrows():
            service: str = row["Service"].lower()
            file_name = f'qmi-service-{service}.json'

            # Add new service file if required
            if file_name not in service_elements:
                service_elements[file_name] = [
                    LibQMIElement(name=service.upper(), type='Service')
                ]

            service_elements[file_name].append(LibQMIElement(
                name=row['Name'],
                type=row['Type'],
                service=service.upper(),
                id=row['Message ID'],
                vendor='Apple (Ghidra)',
            ))

        # Sort the list for each service by the ID of each element
        for service, elements in service_elements.items():
            elements.sort(key=lambda element: element.id if element.id else "")

        # Write the updated data back to disk
        LibQMIJson.write_data_files(directory, service_elements)


def main():
    """ The main function composing the import process. """
    arg_parser = argparse.ArgumentParser(
        prog='import_from_ghidra',
        description='Import libqmi data structures from Ghidra exported CSV files created with the '
                    'ExtractQMIMessageID plugin.'
    )

    arg_parser.add_argument('import_file', type=Path)
    arg_parser.add_argument(
        '--libqmi-data',
        type=Path,
        default=Path(__file__).parent / "libqmi" / "data",
        help='Path to libqmi data files'
    )
    arg_parser.add_argument(
        '--libqmi-ios-extension',
        type=Path,
        default=Path(__file__).parent.parent.parent / "libqmi-ios-ext",
        help='Path to libqmi iOS extension data files'
    )

    args = arg_parser.parse_args()

    import_file: Path = args.import_file
    data_dir: Path = args.libqmi_data
    data_ios_dir: Path = args.libqmi_ios_extension

    if not import_file.is_file():
        sys.stderr.write("The specified file to import does not exists or is not a file!\n")
        sys.exit(1)

    if import_file.suffix != ".csv":
        sys.stderr.write("The specified file to import is not a csv file!\n")
        sys.exit(1)

    if not data_dir.is_dir():
        sys.stderr.write("The specified libqmi data directory does not exists or is not a directory!\n")
        sys.exit(1)

    if not data_ios_dir.is_dir():
        sys.stderr.write("Specified libqmi iOS extension data directory does not exists or is not a directory!\n")
        sys.exit(1)

    extractor = GhidraImporter(data_dir, data_ios_dir, iphone_services)
    import_count = extractor.convert_to_libqmi(import_file)

    print(f"Successfully imported {import_count} packet types into the data directory.")


if __name__ == "__main__":
    main()
