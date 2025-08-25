import dataclasses
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Union

import simplekml

from lib.pb_session_requester import PBRequest, PBSessionRequester
from lib.proto import apple_location_services_pb2 as als_proto

ProtoCellUnionType = Union[
    als_proto.GsmCell, als_proto.ScdmaCell, als_proto.LteCell, als_proto.Nr5GCell, als_proto.CdmaCell]


class ALSTechnology(IntEnum):
    CDMA = 1
    GSM = 2
    SCDMA = 3
    UMTS = 4
    LTE = 5
    NR = 6


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
                technology=ALSTechnology.GSM if not proto_cell.psc else ALSTechnology.UMTS,
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


class AppleLocationService(PBSessionRequester):
    """ The central access point for Apple's Location Services. """

    def __init__(self):
        super().__init__('https://gs-loc.apple.com/clls/wloc')

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
            meta=als_proto.Meta(
                softwareBuild='iPhone OS18.6.2/22G100',
                productId='iPhone17,3'
            ),
            numberOfSurroundingCells=0,
            numberOfSurroundingWifis=1,
            surroundingWifiBands=[als_proto.WifiBand.k2dot4GHZ],
            **request_dict
        )
        # -[ALSLocationRequest requestTypeCode] -> 1
        request = PBRequest(1, proto_request.SerializeToString())
        responses = self._send_http_request([request])
        if len(responses) < 1:
            raise Exception(f"Missing response in binary data")

        proto_response = als_proto.ALSLocationResponse.FromString(responses[0].data)

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
