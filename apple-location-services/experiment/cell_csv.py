from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import pandas


class CSVRadio(Enum):
    """ An enum listing all possible radio techniques stored in the common cell CSV format. """
    GSM = 1
    CDMA = 2
    UMTS = 3
    LTE = 4


@dataclass
class CSVCell:
    """ An object representing a row (cell tower) in the common cell CSV file format. """
    radio: CSVRadio
    mcc: int
    net: int
    area: int
    cell: int
    lon: float
    lat: float
    range: int
    samples: int
    changeable: bool
    created: int
    updated: int
    average_signal: int

    @staticmethod
    def from_csv(csv_row: dict) -> 'CSVCell':
        """
        Converts a row of a CSV file in form of a dictionary into a CSVCellTower object.

        :param csv_row: a dictionary of a CSV row
        :return: a CSVCellTower object with the values of the row
        """
        # radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal
        return CSVCell(
            radio=CSVRadio[csv_row['radio']],
            mcc=int(csv_row['mcc']),
            net=int(csv_row['net']),
            area=int(csv_row['area'] or 0),
            cell=int(csv_row['cell']),
            lon=float(csv_row['lon']),
            lat=float(csv_row['lat']),
            range=int(csv_row['range']),
            samples=int(csv_row['samples']),
            changeable=bool(csv_row['changeable']),
            created=int(csv_row['created']),
            updated=int(csv_row['updated']),
            average_signal=int(csv_row['averageSignal'] or 0)
        )


class CSVCellDatabase:
    """ A reader for the common cell tower CSV format. Only reading the entries for one country.  """
    file: Path
    mcc: list[int]

    def __init__(self, file: Path, mcc: list[int]) -> None:
        self.file = file
        self.mcc = mcc

    def read(self) -> pandas.DataFrame:
        df = pandas.read_csv(self.file)
        return df[df['mcc'].isin(self.mcc)]
