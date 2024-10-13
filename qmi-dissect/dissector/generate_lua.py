#! /usr/bin/python
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.3 generator
#
#    Copyright (c) 2022 Lukas Arnold <lukas.arnold@stud.tu-darmstadt.de>

import argparse
import re
import sys
from pathlib import Path
from typing import Callable, Optional

from qmi_services import iphone_services
from qmi_structures import LibQMIElement, QMIService, LibQMIJson

CommonRefDict = dict[str, LibQMIElement]
""" A type alias for a dictionary mapping names to libqmi objects representing common references. """


class QMIDissector:
    """ A class used to generate a Lua Wireshark dissectors out of the libqmi data JSON files. """
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

    def generate_service_list(self, service_string: Callable[[QMIService], str]) -> str:
        """ Generates a Lua list mapping service ids to strings supplied by the service_string parameter function. """
        code = "{ "
        for service in self.services:
            if service.short_name == "unknown":
                continue
            else:
                code += f"[{service.identifier}] = \"{service_string(service)}\""
            code += ", "
        code += " }"
        return code

    def generate_service_id_list(self) -> str:
        """ Generate the service list which maps service ids to short service names. """
        code = f"services = {self.generate_service_list(lambda service: service.short_name)}\n\n"
        code += "f.svcid = ProtoField.uint8(\"qmi.service_id\", \"Service ID\", base.HEX, services)\n"
        return code

    def generate_service_name_list(self) -> str:
        """ Generate the service list which maps service ids to long service names. """
        code = f"service_names = {self.generate_service_list(lambda service: service.long_name)}\n\n"
        code += "f.svcname = ProtoField.string(\"qmi.service_name\", \"Service Name\", base.UNICODE)\n"
        return code

    @staticmethod
    def collect_common_refs(data_files: dict[str, list[str]]) -> CommonRefDict:
        """ Generate a dictionary of the common refs. """
        common_refs: CommonRefDict = {}

        for file_name, file_texts in data_files.items():
            if "common" not in file_name:
                continue

            for element in LibQMIJson.read_json_data(file_name, file_texts):
                if element.id:
                    common_refs.update({element.common_ref: element})

        return common_refs

    @staticmethod
    def tlv_data_structure(
            element: LibQMIElement, field: str, common_refs: CommonRefDict, common_refs_service: CommonRefDict) -> str:
        """ Convert a single entry item (input, output) of a libqmi JSON file to a Lua list referencing its TLVs. """
        definition = f"[{element.id}] = {{ "

        tlvs: Optional[list[LibQMIElement]] = getattr(element, field)
        if not tlvs:
            definition += "}, "
            return definition

        for tlv in tlvs:
            if tlv.id:
                definition += tlv.lua_map_id_name()
            else:
                if tlv.common_ref:
                    if common_refs.get(tlv.common_ref):
                        common_ref = common_refs.get(tlv.common_ref)
                    elif common_refs_service.get(tlv.common_ref):
                        common_ref = common_refs_service.get(tlv.common_ref)
                    else:
                        print(f"common-ref '{tlv.common_ref}' not found")
                        continue

                    definition += common_ref.lua_map_id_name()
        definition += "}, "

        return definition

    def generate_tlv_data_structures(
            self, data_files: dict[str, list[str]], common_refs: CommonRefDict
    ) -> tuple[str, list[QMIService]]:
        """ Generate requests and related TLVs data structures based on libqmi JSON files. """
        services_name_map = {s.short_name: s for s in self.services}
        found_services = []
        code = ""

        for file_name, file_texts in data_files.items():
            match = re.match("qmi-service-(\\w+)\\.json", file_name)
            if not match:
                continue

            service: QMIService = services_name_map.get(match.group(1))
            if not service:
                print(f"excluded libqmi service {match.group(1)} because it is not in self.services")
                continue

            found_services.append(service)

            messages = ""
            tlv_definitions_req = ""
            tlv_definitions_resp = ""
            indications = ""
            tlv_definitions_ind = ""

            common_refs_service = {}

            for element in LibQMIJson.read_json_data(file_name, file_texts):
                if not element.type:
                    continue

                if element.type == "Message":
                    messages += element.lua_map_id_name()
                    tlv_definitions_req += self.tlv_data_structure(
                        element, "input", common_refs, common_refs_service)
                    tlv_definitions_resp += self.tlv_data_structure(
                        element, "output", common_refs, common_refs_service)
                elif element.type == "Indication":
                    indications += element.lua_map_id_name()
                    tlv_definitions_ind += self.tlv_data_structure(
                        element, "output", common_refs, common_refs_service)
                elif element.type == "TLV":
                    if element.common_ref and element.id:
                        common_refs_service.update({element.common_ref: element})

            field_service_messages = f"service_{service.short_name}_messages"
            field_service_indications = f"service_{service.short_name}_indications"

            code += f"{field_service_messages} = {{ {messages} }}\n\n"
            code += f"{field_service_indications} = {{ {indications} }}\n\n"
            code += f"tlv_{service.short_name}_req = {{ {tlv_definitions_req} }}\n\n"
            code += f"tlv_{service.short_name}_resp = {{ {tlv_definitions_resp} }}\n\n"
            code += f"tlv_{service.short_name}_ind = {{ {tlv_definitions_ind} }}\n\n"

            code += (
                f"f.msgid_{service.short_name} = "
                f"ProtoField.uint16(\"qmi.message_id\", \"Message ID\", base.HEX, {field_service_messages})\n\n")
            code += (
                f"f.indid_{service.short_name} = "
                f"ProtoField.uint16(\"qmi.indication_id\", \"Indication ID\", base.HEX, "
                f"{field_service_indications})\n\n")

        return code, found_services

    @staticmethod
    def link_service_message_type(service: QMIService, type_list: str, id_type: str, tlv_desc: str) -> str:
        """ Generate Lua code to link a QMI service with a specific message type. """
        return (
            f"   mhdrtree:add_le(f.{id_type}id_{service.short_name}, msgid)\n"
            f"   msgstr = service_{service.short_name}_{type_list}[msgid:le_uint()]\n"
            f"   tlv_description = tlv_{service.short_name}_{tlv_desc}\n"
        )

    def link_tlv_data_structures(self, services_with_tlv: list[QMIService]) -> str:
        """ Link TLV data structures to services. """
        code = ""
        first_item = True
        for service in self.services:
            if service.short_name == "unknown":
                continue

            if service not in services_with_tlv:
                continue

            if first_item:
                code += f" if svcid:uint() == {service.identifier} then\n"
                first_item = False
            else:
                code += f" elseif svcid:uint() == {service.identifier} then\n"

            code += f"  if indicationbit == 1 then\n"
            code += self.link_service_message_type(service, "indications", "ind", "ind")

            code += f"  elseif responsebit == 1 then\n"
            code += self.link_service_message_type(service, "messages", "msg", "resp")

            code += f"  else\n"
            code += self.link_service_message_type(service, "messages", "msg", "req")

            code += f"  end\n"

        code += (
            " else\n"
            "  if indicationbit == 1 then\n"
            "   mhdrtree:add_le(f.indid, msgid)\n"
            "  else\n"
            "   mhdrtree:add_le(f.msgid, msgid)\n"
            "  end\n"
            " end\n"
        )

        return code

    @staticmethod
    def lua_tabs(lua_code: str) -> str:
        """ Replace the space characters at the beginning of each line with tab characters. """
        lines = []
        for line in lua_code.splitlines():
            # Replace all space characters at the beginning with tab characters
            # https://stackoverflow.com/a/22149018
            line_chars = list(line)
            for index, char in enumerate(line_chars):
                if char != " ":
                    break
                line_chars[index] = '\t'

            # Append a new line character after each line
            lines.append(f"{''.join(line_chars)}\n")

        return "".join(lines)

    def lua_template(self, template_params: dict) -> Path:
        """ Replace template variables in a Lua template file with template parameters and save the resulting file. """
        template_path = Path(__file__).parent / "qmi_dissector_template.lua"
        output_path = self.build_dir.joinpath("qmi_dissector_gen.lua")
        pattern = re.compile("GENERATE\\((\\w+)\\)")

        with open(template_path, "r") as template_file:
            lines = template_file.readlines()

        for index, line in enumerate(lines):
            match = pattern.search(line)
            if not match:
                continue
            param = match.group(1)
            if not template_params.get(param):
                print(f"Template parameter {param} not found")
                continue
            lines[index] = self.lua_tabs(template_params[param])

        with open(output_path, "w") as output_file:
            output_file.write("".join(lines))

        return output_path

    def generate(self) -> Path:
        """ Generate a Wireshark Dissector based on the class properties and return its location. """
        self.setup_build_dir()
        service_id_list = self.generate_service_id_list()
        service_name_list = self.generate_service_name_list()
        data_files = LibQMIJson.read_data_files([self.data_dir, self.data_ios_dir])
        common_refs = self.collect_common_refs(data_files)
        tlv_data_structures, services_with_tlv = self.generate_tlv_data_structures(data_files, common_refs)
        tlv_link = self.link_tlv_data_structures(services_with_tlv)

        return self.lua_template({
            "QMI_MESSAGE_STRUCTURES": f"{service_id_list}\n{service_name_list}\n{tlv_data_structures}\n",
            "TLV_LINK": f"{tlv_link}\n"
        })


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

    dissector = QMIDissector(build_dir, data_dir, data_ios_dir, iphone_services)
    output_path = dissector.generate()

    print(f"Successfully generated dissector {output_path.name}")


if __name__ == "__main__":
    main()
