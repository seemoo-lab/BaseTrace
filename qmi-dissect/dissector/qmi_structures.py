import json
from dataclasses import dataclass
from itertools import chain
from json import JSONEncoder
from pathlib import Path
from typing import Optional, List, Any


@dataclass
class QMIService:
    """ A class representing a service in the QMI protocol. """

    identifier: int
    short_name: str
    long_name: str
    libqmi_name: Optional[str] = None

    def field(self, prefix: str = "", suffix: str = "") -> str:
        """ Builds a Lua field name with the given prefix and suffix based on the short_name of the service. """
        field_name = self.short_name
        if prefix:
            field_name = f"{prefix}_{field_name}"
        if suffix:
            field_name = f"{field_name}_{suffix}"
        return field_name


@dataclass
class LibQMIElement:
    """ A data class representing an object at every level from the libqmi data JSON files. """
    common_ref: Optional[str] = None

    name: Optional[str] = None
    id: Optional[str] = None
    type: Optional[str] = None
    since: Optional[str] = None

    service: Optional[str] = None
    vendor: Optional[str] = None

    input: Optional[List["LibQMIElement"]] = None
    output: Optional[List["LibQMIElement"]] = None

    personal_info: Optional[str] = None
    format: Optional[str] = None
    public_format: Optional[str] = None
    fixed_size: Optional[str] = None
    max_size: Optional[str] = None
    size_prefix_format: Optional[str] = None
    guint_size: Optional[str] = None
    protobuf_message: Optional[str] = None

    contents: Optional[List["LibQMIElement"]] = None
    prerequisites: Optional[List["LibQMIElement"]] = None
    array_element: Optional["LibQMIElement"] = None

    def lua_map_id_name(self) -> str:
        """ Returns a Lua snippet used in Lua tables to map the elements id to its name """
        if self.name:
            return f"[{self.id}] = '{self.name}', "
        else:
            return f"[{self.id}] = 'unknown name', "

    @staticmethod
    def from_json(data: dict) -> "LibQMIElement":
        """ Parses a JSON dictionary from json.laods into a LibQMIElement """
        return LibQMIElement(
            common_ref=data.get("common-ref"),

            name=data.get("name"),
            id=data.get("id"),
            type=data.get("type"),
            since=data.get("since"),

            service=data.get("service"),
            vendor=data.get("vendor"),

            input=data.get("input"),
            output=data.get("output"),

            format=data.get("format"),
            public_format=data.get("public-format"),
            fixed_size=data.get('fixed-size'),
            max_size=data.get("max-size"),
            size_prefix_format=data.get("size-prefix-format"),
            personal_info=data.get("personal-info"),
            guint_size=data.get("guint-size"),
            protobuf_message=data.get("protobuf-message"),

            contents=data.get("contents"),
            prerequisites=data.get("prerequisites"),
            array_element=data.get("array-element")
        )


class LibQMIElementEncoder(JSONEncoder):
    def default(self, o: Any) -> Any:
        # Convert the LibQMIElement Python object into a dictionary of its values.
        # See: https://stackoverflow.com/a/3768975
        values: dict = o.__dict__

        # Remove the None value to prevent clutter of the final JSON file.
        # See: https://stackoverflow.com/a/21412056
        values = {k: v for (k, v) in values.items() if v is not None}

        return values


class LibQMIJson:
    @staticmethod
    def polish_json(source: Path) -> str:
        """ Remove unwanted lines from a JSON file (source) and return its polished version. """
        bad_words = ["//"]

        with open(source) as src_file:
            lines = src_file.readlines()

            # Replace all lines with bad words with empty ones to keep the line numbers correct
            for index, line in enumerate(lines):
                if any(bad_word in line for bad_word in bad_words):
                    lines[index] = "\n"

        return "".join(lines)

    @staticmethod
    def read_data_files(dirs: list[Path], sub_dirs: bool = True) -> dict[str, list[str]]:
        """ Read all JSON files in the data_dir (and by default its subdirectories) and return them as a dictionary. """
        rename_services = {
            'qmi-service-voice.json': 'qmi-service-vs.json',
            'qmi-service-cat2.json': 'qmi-service-cat.json'
        }
        data_files = {}
        for path in chain(*map(lambda dir: dir.glob("**/*.json" if sub_dirs else "*.json"), dirs)):
            name = path.name

            # Rename libqmi service definition files to fit with iOS QMI service names
            if name in rename_services:
                name = rename_services[name]

            if name in data_files:
                data_files[name].append(LibQMIJson.polish_json(path))
            else:
                data_files[name] = [LibQMIJson.polish_json(path)]

        return data_files

    @staticmethod
    def read_json_data(file_name: str, file_texts: list[str]) -> list[LibQMIElement]:
        """ Reads the JSON data from data files into LibQMIElements. """
        json_data: list[LibQMIElement] = []

        for file_text in file_texts:
            try:
                json_data.extend(json.loads(file_text, object_hook=LibQMIElement.from_json))
            except json.decoder.JSONDecodeError as json_error:
                print(f"Unable to decode JSON file {file_name} - {json_error}")
                continue

        return json_data

    @staticmethod
    def write_data_files(data_dir: Path, data_files: dict[str, list[LibQMIElement]]):
        """ Writes the data of all QMI services back to JSON files in the specified directory. """
        for file_name, file_data in data_files.items():
            file_path = data_dir.joinpath(file_name)
            file_path.write_text(json.dumps(file_data, indent=4, cls=LibQMIElementEncoder))
