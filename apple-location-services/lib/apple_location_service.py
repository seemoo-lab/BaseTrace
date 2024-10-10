import dataclasses
import http.client
import struct
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union

import simplekml

from lib import core_location_als_pb2 as als_proto

ProtoCellUnionType = Union[
    als_proto.GsmCell, als_proto.ScdmaCell, als_proto.LteCell, als_proto.Nr5GCell, als_proto.CdmaCell]


class ALSTechnology(Enum):
    GSM = 1
    SCDMA = 2
    LTE = 3
    NR = 4
    CDMA = 5


@dataclass(eq=True, frozen=True)
class ALSLocation:
    """ Class for storing an ALS location """
    latitude: float
    longitude: float
    accuracy: int
    reach: int
    score: int

    def is_valid(self) -> bool:
        return self.accuracy >= 0

    @staticmethod
    def from_proto(proto_location: als_proto.Location) -> 'ALSLocation':
        return ALSLocation(
            latitude=proto_location.latitude * pow(10, -8),
            longitude=proto_location.longitude * pow(10, -8),
            accuracy=proto_location.accuracy,
            reach=proto_location.reach,
            score=proto_location.score
        )


@dataclass(eq=True, frozen=True)
class ALSCell:
    """ Class for storing an ALS cell tower (including a location) """
    technology: ALSTechnology
    country: int
    network: int
    area: int
    cell: int
    location: Optional[ALSLocation]

    def has_cell(self) -> bool:
        return self.cell >= 0

    def is_valid(self) -> bool:
        return self.location and self.location.is_valid()

    def strip_location(self) -> 'ALSCell':
        return dataclasses.replace(self, location=None)

    def to_proto(self) -> ProtoCellUnionType:
        if self.technology == ALSTechnology.GSM:
            return als_proto.GsmCell(
                mcc=self.country,
                mnc=self.network,
                lacID=self.area,
                cellID=self.cell
            )
        elif self.technology == ALSTechnology.SCDMA:
            return als_proto.ScdmaCell(
                mcc=self.country,
                mnc=self.network,
                lacID=self.area,
                cellID=self.cell
            )
        elif self.technology == ALSTechnology.LTE:
            return als_proto.LteCell(
                mcc=self.country,
                mnc=self.network,
                tacID=self.area,
                cellID=self.cell
            )
        elif self.technology == ALSTechnology.NR:
            return als_proto.Nr5GCell(
                mcc=self.country,
                mnc=self.network,
                tacID=self.area,
                cellID=self.cell
            )
        elif self.technology == ALSTechnology.CDMA:
            # Mapping is similar to the OpenCellid API
            # See: http://wiki.opencellid.org/wiki/API
            return als_proto.CdmaCell(
                mcc=self.country,
                sid=self.network,
                nid=self.area,
                bsid=self.cell
            )
        else:
            raise Exception(f"Unknown ALSTechnology: {self.technology.name}")

    def to_kml_point(self, kml: simplekml.Kml):
        if not self.location:
            raise Exception(f"No ALSLocation stored")
        if not self.is_valid():
            raise Exception(f"Not valid")

        location = self.location
        point: simplekml.Point = kml.newpoint(
            name=f"{self.technology.name}/{self.country}/{self.network}/{self.area}/{self.cell}",
            description=f"Technology: <b>{self.technology.name}</b><br/>\n"
                        f"Country: <b>{self.country}</b><br/>\n"
                        f"Network: <b>{self.network}</b><br/>\n"
                        f"Area: <b>{self.area}</b><br/>\n"
                        f"Cell ID: <b>{self.cell}</b><br/>\n"
                        f"<br/>\n"
                        f"Accuracy: <b>{location.accuracy}m</b><br/>\n"
                        f"Reach: <b>{location.reach}m</b><br/>\n"
                        f"Score: <b>{location.score}</b><br/>\n",
            coords=[(location.longitude, location.latitude)],
        )
        # TODO: Set color based on RAT
        if self.cell >= 0:
            # Use the default blue balloon icon from Google Earth Web
            # For more icons, see http://kml4earth.appspot.com/icons.html
            point.style.iconstyle.icon.href = 'https://earth.google.com/earth/rpc/cc/icon?color=1976d2&id=2000&scale=4'
        else:
            # Use the blue balloon icon from Google Earth Web with a rotated square inside
            point.style.iconstyle.icon.href = 'https://earth.google.com/earth/rpc/cc/icon?color=1976d2&id=2002&scale=4'
        # Don't show the icon's label
        point.style.labelstyle.scale = 0

    @staticmethod
    def from_proto(proto_cell: ProtoCellUnionType) -> 'ALSCell':
        location = ALSLocation.from_proto(proto_cell.location)
        if isinstance(proto_cell, als_proto.GsmCell):
            return ALSCell(
                technology=ALSTechnology.GSM,
                country=proto_cell.mcc,
                network=proto_cell.mnc,
                area=proto_cell.lacID,
                cell=proto_cell.cellID,
                location=location
            )
        elif isinstance(proto_cell, als_proto.ScdmaCell):
            return ALSCell(
                technology=ALSTechnology.SCDMA,
                country=proto_cell.mcc,
                network=proto_cell.mnc,
                area=proto_cell.lacID,
                cell=proto_cell.cellID,
                location=location
            )
        elif isinstance(proto_cell, als_proto.LteCell):
            return ALSCell(
                technology=ALSTechnology.LTE,
                country=proto_cell.mcc,
                network=proto_cell.mnc,
                area=proto_cell.tacID,
                cell=proto_cell.cellID,
                location=location
            )
        elif isinstance(proto_cell, als_proto.Nr5GCell):
            return ALSCell(
                technology=ALSTechnology.NR,
                country=proto_cell.mcc,
                network=proto_cell.mnc,
                area=proto_cell.tacID,
                cell=proto_cell.cellID,
                location=location
            )
        elif isinstance(proto_cell, als_proto.CdmaCell):
            return ALSCell(
                technology=ALSTechnology.CDMA,
                country=proto_cell.mcc,
                network=proto_cell.sid,
                area=proto_cell.nid,
                cell=proto_cell.bsid,
                location=location
            )
        else:
            raise Exception(f"Unknown Protobuf cell: {proto_cell.__class__}")


class AppleLocationService:
    """ The central access point for Apple's Location Services. """

    endpoint = 'https://gs-loc.apple.com/clls/wloc'
    headers = {
        'User-Agent': 'locationd/2420.8.11 CFNetwork/1206 Darwin/20.1.0',
        'Accept': '*/*',
        'Accept-Language': 'en-us',
    }
    service_identifier = 'com.apple.locationd'
    ios_version = '14.2.1.18B121'
    locale = 'en_US'

    def request_cells(self, origin_cell: ALSCell) -> list[ALSCell]:
        """
        Request nearby cell towers. The origin_cell parameter doesn't require a location.

        :param origin_cell: the cell used as a request parameter and the origin of the query
        :return: a list of received nearby cells
        """
        request_dict = {}
        if origin_cell.technology == ALSTechnology.GSM:
            request_dict['gsmCells'] = [origin_cell.to_proto()]
        elif origin_cell.technology == ALSTechnology.SCDMA:
            request_dict['scdmaCells'] = [origin_cell.to_proto()]
        elif origin_cell.technology == ALSTechnology.LTE:
            request_dict['lteCells'] = [origin_cell.to_proto()]
        elif origin_cell.technology == ALSTechnology.NR:
            request_dict['nr5GCells'] = [origin_cell.to_proto()]
        elif origin_cell.technology == ALSTechnology.CDMA:
            # It works, but only returns an empty CDMA cell.
            # Presumably because all CDMA networks in the USA have been shut down.
            # Thus, we are unable to verify it.
            request_dict['cdmaCells'] = [origin_cell.to_proto()]
            request_dict['cdmaEvdoCells'] = [origin_cell.to_proto()]
        else:
            raise Exception(f"Unknown ALSTechnology: {origin_cell.technology.name}")

        proto_request = als_proto.ALSLocationRequest(
            numberOfSurroundingCells=0,
            numberOfSurroundingWifis=1,
            surroundingWifiBands=[1],
            **request_dict
        )
        response_body = self._send_http_request(proto_request.SerializeToString())
        proto_response = als_proto.ALSLocationResponse()
        proto_response.ParseFromString(response_body)

        cells: list[ALSCell] = []

        for cell in proto_response.gsmCells:
            cells.append(ALSCell.from_proto(cell))

        for cell in proto_response.scdmaCells:
            cells.append(ALSCell.from_proto(cell))

        for cell in proto_response.lteCells:
            cells.append(ALSCell.from_proto(cell))

        for cell in proto_response.nr5GCells:
            cells.append(ALSCell.from_proto(cell))

        for cell in proto_response.cdmaCells:
            cells.append(ALSCell.from_proto(cell))

        return cells

    def _send_http_request(self, proto_data: bytes) -> bytes:
        """
        Send an HTTP request to Apple's Location Service.
        The proto_data parameter is automatically appended to the binary header.

        :param proto_data: Encoded data for the request body
        :return: the bytes of the response body
        """
        http_data = self._build_header() + self._pack_length(len(proto_data)) + proto_data

        http_request = urllib.request.Request(self.endpoint, data=http_data, headers=self.headers, method='POST')
        http_response: http.client.HTTPResponse
        with urllib.request.urlopen(http_request) as http_response:
            if http_response.status != 200:
                raise Exception(f'Unexpected HTTP status code, got {http_response.status}, wanted 200')

            # Remove the first ten bytes, because they also contain a TLV header: start + end + start + end + size
            # e.g. 00 01 00 00 00 01 00 00 16 79
            return http_response.read()[10:]

    def _build_header(self) -> bytes:
        """
        Build the TLV (type length value) header bytes for an ALS request.

        :return: header bytes for a request to ALS
        """
        start = b'\x00\x01'
        end = b'\x00\x00'

        # Store the start value
        header = start

        # Store the locale length using a 2 byte short with big endianness (network default)
        header += self._pack_length(len(self.locale))
        # Store the encoded locale itself
        header += self.locale.encode()

        # Done similar for the service identifier
        header += self._pack_length(len(self.service_identifier))
        header += self.service_identifier.encode()

        # Done similar for the version
        header += self._pack_length(len(self.ios_version))
        header += self.ios_version.encode()

        # Store the end value
        header += end
        header += start
        header += end

        return header

    @staticmethod
    def _pack_length(length: int) -> bytes:
        """
        Pack the given length value (in bytes) into a signed short (2 bytes) with big endianness (network default).
        See: https://docs.python.org/3.9/library/struct.html#byte-order-size-and-alignment

        :return: packed value
        """
        return struct.pack('!h', length)
