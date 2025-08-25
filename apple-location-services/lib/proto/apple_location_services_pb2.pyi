from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AltitudeScale(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    None: _ClassVar[AltitudeScale]
    Scale10toThe2: _ClassVar[AltitudeScale]

class WifiBand(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    k2dot4GHZ: _ClassVar[WifiBand]
    k5GHZ: _ClassVar[WifiBand]
None: AltitudeScale
Scale10toThe2: AltitudeScale
k2dot4GHZ: WifiBand
k5GHZ: WifiBand

class Meta(_message.Message):
    __slots__ = ("softwareBuild", "productId")
    SOFTWAREBUILD_FIELD_NUMBER: _ClassVar[int]
    PRODUCTID_FIELD_NUMBER: _ClassVar[int]
    softwareBuild: str
    productId: str
    def __init__(self, softwareBuild: _Optional[str] = ..., productId: _Optional[str] = ...) -> None: ...

class Location(_message.Message):
    __slots__ = ("latitude", "longitude", "accuracy", "locationType", "altitude", "verticalAccuracy", "reach", "score", "infoMask")
    LATITUDE_FIELD_NUMBER: _ClassVar[int]
    LONGITUDE_FIELD_NUMBER: _ClassVar[int]
    ACCURACY_FIELD_NUMBER: _ClassVar[int]
    LOCATIONTYPE_FIELD_NUMBER: _ClassVar[int]
    ALTITUDE_FIELD_NUMBER: _ClassVar[int]
    VERTICALACCURACY_FIELD_NUMBER: _ClassVar[int]
    REACH_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    INFOMASK_FIELD_NUMBER: _ClassVar[int]
    latitude: int
    longitude: int
    accuracy: int
    locationType: int
    altitude: int
    verticalAccuracy: int
    reach: int
    score: int
    infoMask: int
    def __init__(self, latitude: _Optional[int] = ..., longitude: _Optional[int] = ..., accuracy: _Optional[int] = ..., locationType: _Optional[int] = ..., altitude: _Optional[int] = ..., verticalAccuracy: _Optional[int] = ..., reach: _Optional[int] = ..., score: _Optional[int] = ..., infoMask: _Optional[int] = ...) -> None: ...

class WirelessAP(_message.Message):
    __slots__ = ("macID", "location", "channel", "numZAxisHarvestTraces")
    MACID_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    NUMZAXISHARVESTTRACES_FIELD_NUMBER: _ClassVar[int]
    macID: str
    location: Location
    channel: int
    numZAxisHarvestTraces: int
    def __init__(self, macID: _Optional[str] = ..., location: _Optional[_Union[Location, _Mapping]] = ..., channel: _Optional[int] = ..., numZAxisHarvestTraces: _Optional[int] = ...) -> None: ...

class Nr5GCell(_message.Message):
    __slots__ = ("mcc", "mnc", "cellID", "tacID", "location", "nrarfcn")
    MCC_FIELD_NUMBER: _ClassVar[int]
    MNC_FIELD_NUMBER: _ClassVar[int]
    CELLID_FIELD_NUMBER: _ClassVar[int]
    TACID_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    NRARFCN_FIELD_NUMBER: _ClassVar[int]
    mcc: int
    mnc: int
    cellID: int
    tacID: int
    location: Location
    nrarfcn: int
    def __init__(self, mcc: _Optional[int] = ..., mnc: _Optional[int] = ..., cellID: _Optional[int] = ..., tacID: _Optional[int] = ..., location: _Optional[_Union[Location, _Mapping]] = ..., nrarfcn: _Optional[int] = ...) -> None: ...

class ScdmaCell(_message.Message):
    __slots__ = ("mcc", "mnc", "cellID", "lacID", "location", "arfcn", "psc")
    MCC_FIELD_NUMBER: _ClassVar[int]
    MNC_FIELD_NUMBER: _ClassVar[int]
    CELLID_FIELD_NUMBER: _ClassVar[int]
    LACID_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    ARFCN_FIELD_NUMBER: _ClassVar[int]
    PSC_FIELD_NUMBER: _ClassVar[int]
    mcc: int
    mnc: int
    cellID: int
    lacID: int
    location: Location
    arfcn: int
    psc: int
    def __init__(self, mcc: _Optional[int] = ..., mnc: _Optional[int] = ..., cellID: _Optional[int] = ..., lacID: _Optional[int] = ..., location: _Optional[_Union[Location, _Mapping]] = ..., arfcn: _Optional[int] = ..., psc: _Optional[int] = ...) -> None: ...

class LteCell(_message.Message):
    __slots__ = ("mcc", "mnc", "cellID", "tacID", "location", "uarfcn", "pid")
    MCC_FIELD_NUMBER: _ClassVar[int]
    MNC_FIELD_NUMBER: _ClassVar[int]
    CELLID_FIELD_NUMBER: _ClassVar[int]
    TACID_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    UARFCN_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    mcc: int
    mnc: int
    cellID: int
    tacID: int
    location: Location
    uarfcn: int
    pid: int
    def __init__(self, mcc: _Optional[int] = ..., mnc: _Optional[int] = ..., cellID: _Optional[int] = ..., tacID: _Optional[int] = ..., location: _Optional[_Union[Location, _Mapping]] = ..., uarfcn: _Optional[int] = ..., pid: _Optional[int] = ...) -> None: ...

class GsmCell(_message.Message):
    __slots__ = ("mcc", "mnc", "cellID", "lacID", "location", "arfcn", "psc")
    MCC_FIELD_NUMBER: _ClassVar[int]
    MNC_FIELD_NUMBER: _ClassVar[int]
    CELLID_FIELD_NUMBER: _ClassVar[int]
    LACID_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    ARFCN_FIELD_NUMBER: _ClassVar[int]
    PSC_FIELD_NUMBER: _ClassVar[int]
    mcc: int
    mnc: int
    cellID: int
    lacID: int
    location: Location
    arfcn: int
    psc: int
    def __init__(self, mcc: _Optional[int] = ..., mnc: _Optional[int] = ..., cellID: _Optional[int] = ..., lacID: _Optional[int] = ..., location: _Optional[_Union[Location, _Mapping]] = ..., arfcn: _Optional[int] = ..., psc: _Optional[int] = ...) -> None: ...

class CdmaCell(_message.Message):
    __slots__ = ("mcc", "sid", "nid", "bsid", "location", "zoneid", "bandclass", "channel", "pnoffset")
    MCC_FIELD_NUMBER: _ClassVar[int]
    SID_FIELD_NUMBER: _ClassVar[int]
    NID_FIELD_NUMBER: _ClassVar[int]
    BSID_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    ZONEID_FIELD_NUMBER: _ClassVar[int]
    BANDCLASS_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    PNOFFSET_FIELD_NUMBER: _ClassVar[int]
    mcc: int
    sid: int
    nid: int
    bsid: int
    location: Location
    zoneid: int
    bandclass: int
    channel: int
    pnoffset: int
    def __init__(self, mcc: _Optional[int] = ..., sid: _Optional[int] = ..., nid: _Optional[int] = ..., bsid: _Optional[int] = ..., location: _Optional[_Union[Location, _Mapping]] = ..., zoneid: _Optional[int] = ..., bandclass: _Optional[int] = ..., channel: _Optional[int] = ..., pnoffset: _Optional[int] = ...) -> None: ...

class ALSLocationRequest(_message.Message):
    __slots__ = ("gsmCells", "wirelessAPs", "numberOfSurroundingCells", "numberOfSurroundingWifis", "appBundleId", "cdmaCells", "cdmaEvdoCells", "numberOfSurroundingCdmaCells", "numberOfSurroundingCdmaEvdoCells", "lteCells", "numberOfSurroundingLteCells", "scdmaCells", "numberOfSurroundingScdmaCells", "nr5GCells", "numberOfSurroundingNr5GCells", "surroundingWifiBands", "wifiAltitudeScale", "meta")
    GSMCELLS_FIELD_NUMBER: _ClassVar[int]
    WIRELESSAPS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSURROUNDINGCELLS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSURROUNDINGWIFIS_FIELD_NUMBER: _ClassVar[int]
    APPBUNDLEID_FIELD_NUMBER: _ClassVar[int]
    CDMACELLS_FIELD_NUMBER: _ClassVar[int]
    CDMAEVDOCELLS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSURROUNDINGCDMACELLS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSURROUNDINGCDMAEVDOCELLS_FIELD_NUMBER: _ClassVar[int]
    LTECELLS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSURROUNDINGLTECELLS_FIELD_NUMBER: _ClassVar[int]
    SCDMACELLS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSURROUNDINGSCDMACELLS_FIELD_NUMBER: _ClassVar[int]
    NR5GCELLS_FIELD_NUMBER: _ClassVar[int]
    NUMBEROFSURROUNDINGNR5GCELLS_FIELD_NUMBER: _ClassVar[int]
    SURROUNDINGWIFIBANDS_FIELD_NUMBER: _ClassVar[int]
    WIFIALTITUDESCALE_FIELD_NUMBER: _ClassVar[int]
    META_FIELD_NUMBER: _ClassVar[int]
    gsmCells: _containers.RepeatedCompositeFieldContainer[GsmCell]
    wirelessAPs: _containers.RepeatedCompositeFieldContainer[WirelessAP]
    numberOfSurroundingCells: int
    numberOfSurroundingWifis: int
    appBundleId: str
    cdmaCells: _containers.RepeatedCompositeFieldContainer[CdmaCell]
    cdmaEvdoCells: _containers.RepeatedCompositeFieldContainer[CdmaCell]
    numberOfSurroundingCdmaCells: int
    numberOfSurroundingCdmaEvdoCells: int
    lteCells: _containers.RepeatedCompositeFieldContainer[LteCell]
    numberOfSurroundingLteCells: int
    scdmaCells: _containers.RepeatedCompositeFieldContainer[ScdmaCell]
    numberOfSurroundingScdmaCells: int
    nr5GCells: _containers.RepeatedCompositeFieldContainer[Nr5GCell]
    numberOfSurroundingNr5GCells: int
    surroundingWifiBands: _containers.RepeatedScalarFieldContainer[WifiBand]
    wifiAltitudeScale: AltitudeScale
    meta: Meta
    def __init__(self, gsmCells: _Optional[_Iterable[_Union[GsmCell, _Mapping]]] = ..., wirelessAPs: _Optional[_Iterable[_Union[WirelessAP, _Mapping]]] = ..., numberOfSurroundingCells: _Optional[int] = ..., numberOfSurroundingWifis: _Optional[int] = ..., appBundleId: _Optional[str] = ..., cdmaCells: _Optional[_Iterable[_Union[CdmaCell, _Mapping]]] = ..., cdmaEvdoCells: _Optional[_Iterable[_Union[CdmaCell, _Mapping]]] = ..., numberOfSurroundingCdmaCells: _Optional[int] = ..., numberOfSurroundingCdmaEvdoCells: _Optional[int] = ..., lteCells: _Optional[_Iterable[_Union[LteCell, _Mapping]]] = ..., numberOfSurroundingLteCells: _Optional[int] = ..., scdmaCells: _Optional[_Iterable[_Union[ScdmaCell, _Mapping]]] = ..., numberOfSurroundingScdmaCells: _Optional[int] = ..., nr5GCells: _Optional[_Iterable[_Union[Nr5GCell, _Mapping]]] = ..., numberOfSurroundingNr5GCells: _Optional[int] = ..., surroundingWifiBands: _Optional[_Iterable[_Union[WifiBand, str]]] = ..., wifiAltitudeScale: _Optional[_Union[AltitudeScale, str]] = ..., meta: _Optional[_Union[Meta, _Mapping]] = ...) -> None: ...

class ALSLocationResponse(_message.Message):
    __slots__ = ("gsmCells", "wirelessAPs", "cdmaCells", "lteCells", "scdmaCells", "nr5GCells")
    GSMCELLS_FIELD_NUMBER: _ClassVar[int]
    WIRELESSAPS_FIELD_NUMBER: _ClassVar[int]
    CDMACELLS_FIELD_NUMBER: _ClassVar[int]
    LTECELLS_FIELD_NUMBER: _ClassVar[int]
    SCDMACELLS_FIELD_NUMBER: _ClassVar[int]
    NR5GCELLS_FIELD_NUMBER: _ClassVar[int]
    gsmCells: _containers.RepeatedCompositeFieldContainer[GsmCell]
    wirelessAPs: _containers.RepeatedCompositeFieldContainer[WirelessAP]
    cdmaCells: _containers.RepeatedCompositeFieldContainer[CdmaCell]
    lteCells: _containers.RepeatedCompositeFieldContainer[LteCell]
    scdmaCells: _containers.RepeatedCompositeFieldContainer[ScdmaCell]
    nr5GCells: _containers.RepeatedCompositeFieldContainer[Nr5GCell]
    def __init__(self, gsmCells: _Optional[_Iterable[_Union[GsmCell, _Mapping]]] = ..., wirelessAPs: _Optional[_Iterable[_Union[WirelessAP, _Mapping]]] = ..., cdmaCells: _Optional[_Iterable[_Union[CdmaCell, _Mapping]]] = ..., lteCells: _Optional[_Iterable[_Union[LteCell, _Mapping]]] = ..., scdmaCells: _Optional[_Iterable[_Union[ScdmaCell, _Mapping]]] = ..., nr5GCells: _Optional[_Iterable[_Union[Nr5GCell, _Mapping]]] = ...) -> None: ...
