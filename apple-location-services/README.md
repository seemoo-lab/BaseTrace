# Apple Location Service

A library and a command line client for querying cells stored in Apple's Location Service database.

## Command Line Client

You can query for nearby cells using the command line client:
```bash
# Install pipenv
pip3 install pipenv

# Create virtual environment and sync all dependencies
pipenv sync

# ./als_cli.py [-h] {gsm,scdma,umts,lte,nr,cdma} country network area cell
# Search for nearby UMTS / LTE cell towers of a cell tower in Germany (262) 
# from Vodafone (2) in area 46452 with the cell tower id 15669002.
pipenv run python3 als_cli.py lte 262 2 46452 15669002
# Search for nearby GSM cell towers of a cell tower in Germany (262) 
# from Vodafone (2) in area 566 with the cell tower id 4461.
pipenv run python3 als_cli.py gsm 262 2 566 4461
```

## Library

The Python library for accessing Apple's Location Service can be found in the [`lib`](./lib) folder.

## Experiment

An experiment comparing Apple's Location Service database with open cell databases can be found in the [`experiment`](./experiment) folder.

## Development

For development, install the Python dependencies using pipenv as shown above.

If you want to edit the Protocol Buffer file, you'll also need [Google's Protobuf](https://developers.google.com/protocol-buffers) compiler `protoc`:
- Linux: `apt install protobuf-compiler`
- Mac: `brew install protoc`
- Windows: `scoop install protobuf`

Once, you've installed everything, you can run the proto script to update the generated Python files.
```bash
pipenv run proto
```

Good resources on Protocol Buffers:
- https://developers.google.com/protocol-buffers/docs/proto
- https://developers.google.com/protocol-buffers/docs/pythontutorial

## CellGuard Protobuf

The iOS app CellGuard also depends on the Apple Location Service and therefore makes use of the protobuf file.

In order to generate the related Swift file, a additional protoc plugin for Swift must be installed.
More information can be found at [apple/swift-protobuf](https://github.com/apple/swift-protobuf).

```bash
# Install the additional Swift protobuf plugin
brew install swift-protobuf
# Generate the Swift in the folder swift
protoc --swift_out=swift apple-location-services.proto
```

## CellGuard Evaluation

The directory [`cellguard`](./cellguard) contains a Python script to evaluate cell files exported by the CellGuard iOS app.

## References

- https://github.com/zadewg/GS-LOC
- https://www.appelsiini.net/2017/reverse-engineering-location-services/
