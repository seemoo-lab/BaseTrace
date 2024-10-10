import argparse
import csv
import functools
import json
import random
import traceback
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import pandas
from tqdm import tqdm

from experiment.cell_csv import CSVCellDatabase
from lib.apple_location_service import AppleLocationService, ALSCell, ALSTechnology


class ExperimentPhase(Enum):
    """ An enum representing the current phase of a experiment. """
    COLLECTING = 1
    ANALYZING = 2
    FINISHED = 3


@dataclass
class ExperimentState:
    """ A data class for storing the current state of the experiment to disk. """
    index: int
    skipped: list[int]
    phase: ExperimentPhase
    mcc: list[int]
    sample_size: int
    database: Path
    technologies: list[str]
    start_time: datetime

    def store(self, path: Path) -> None:
        """ Store the current state as a JSON file to the given path. """
        with open(path, 'w') as file:
            json.dump({
                'index': self.index,
                'skipped': self.skipped,
                'phase': self.phase.name,
                'mcc': self.mcc,
                'sample_size': self.sample_size,
                'database': str(self.database),
                'technologies': self.technologies,
                'start_time': self.start_time.timestamp()
            }, file)

    @staticmethod
    def from_json(data: dict) -> 'ExperimentState':
        """ Deserialize a JSON dictionary to an experiment state object. """
        return ExperimentState(
            index=data['index'],
            skipped=data['skipped'],
            phase=ExperimentPhase[data['phase']],
            mcc=data.get('mcc'),
            sample_size=data.get('sample_size'),
            database=Path(data.get('database')),
            technologies=data.get('technologies'),
            start_time=datetime.fromtimestamp(data.get('start_time'))
        )

    @staticmethod
    def read(path: Path) -> 'ExperimentState':
        """ Read the state from a JSON file available at the given path. """
        with open(path, 'r') as file:
            return json.load(file, object_hook=ExperimentState.from_json)

    def __str__(self) -> str:
        """ Return a string representation of the current state """
        return f'State{{ phase={self.phase},index={self.index},len(skipped)={len(self.skipped)} }}'


class NearbyCellExperiment:
    """ The class responsible for performing the nearby cell experiment (colling data & analyzing it). """
    size: int
    mcc: list[int]
    database_path: Path
    verbose: bool
    seed: int
    technologies: list[str]

    sample_path: Path
    als_cells_path: Path
    state_path: Path

    def __init__(self, size: int, mcc: list[int], database: Path, verbose: bool, seed: int, technologies: list[str]):
        self.size = size
        self.mcc = mcc
        self.database_path = database
        self.verbose = verbose
        self.seed = seed
        self.technologies = technologies

        self.sample_path = self._folder().joinpath('sample.csv')
        self.als_cells_path = self._folder().joinpath('als-cells.csv')
        self.state_path = self._folder().joinpath('state.json')

    def _folder(self) -> Path:
        """ Returns the path the folder for this experiment. """
        mcc_str = '_'.join(map(str, self.mcc))
        return Path(f'experiment_{mcc_str}_{self.size}_{hex(self.seed)}').absolute()

    @staticmethod
    def _cell_to_dict(cell: ALSCell, row: Any) -> dict:
        """ Converts an Apple Location Service Cell object to a dictionary that can be used in a pandas data frame. """
        return {
            'technology': cell.technology.name,
            'mcc': cell.country,
            'mnc': cell.network,
            'tac': cell.area,
            'cell': cell.cell,
            'latitude': cell.location.latitude,
            'longitude': cell.location.longitude,
            'accuracy': cell.location.accuracy,
            'reach': cell.location.reach,
            'score': cell.location.score,
            'from_technology': row.radio,
            'from_mcc': row.mcc,
            'from_mnc': row.net,
            'from_tac': row.area,
            'from_cell': row.cell,
        }

    def _collect_data(self) -> tuple[pandas.DataFrame, pandas.DataFrame, ExperimentState]:
        """ Requests nearby cells from Apple's Location Service using a sample from the given cell database. """
        sample: pandas.DataFrame
        als_cells: csv.DictWriter
        state: ExperimentState

        print('== Collection (Start) ==')
        print(f'Experiment data folder: {self._folder()}')

        # Check if the folder already, allowing for resumption of an aborted experiment
        if self._folder().exists():
            print(f'Folder exists, resuming experiment...')

            sample = pandas.read_csv(self.sample_path)
            state = ExperimentState.read(self.state_path)

            print(f'It was originally started on {state.start_time.strftime("%c")}')

            if state.mcc != self.mcc:
                print(f'State Warning: Stored MCC ({state.mcc}) differs from the provided MCC ({self.mcc})')

            if state.sample_size != self.size:
                print(f'State Warning: Stored sample size ({state.sample_size}) '
                      f'differs from the provided sample size ({self.size})')

            if state.database != Path(self.database_path):
                print(f'State Warning: Stored database path ({state.database}) '
                      f'differs from the provided database path ({self.database_path})')

            if state.technologies != self.technologies:
                print(f'State Warning: Stored considered technologies ({state.technologies}) '
                      f'differs from the provided considered technologies ({self.technologies})')

            if state.phase != ExperimentPhase.COLLECTING:
                print('Reading the collected data into memory...')
                als_cells_data_frame = pandas.read_csv(self.als_cells_path)

                print('== Collection (End) ==')

                return sample, als_cells_data_frame, state
        else:
            print(f'Created new folder, starting experiment from scratch...')
            self._folder().mkdir()
            start_time = datetime.now()

            database = CSVCellDatabase(self.database_path, self.mcc)
            open_database = database.read()

            print(f'Considering the following radio technologies for sampling: {self.technologies}')
            open_database = open_database[open_database['radio'].isin(self.technologies)]

            sample = open_database.sample(n=self.size, random_state=self.seed).reset_index()
            sample.to_csv(self.sample_path)

            print(f'Sample size: {len(sample.index)}')

            state = ExperimentState(
                index=0, skipped=[], phase=ExperimentPhase.COLLECTING,
                mcc=self.mcc, sample_size=self.size, database=self.database_path,
                technologies=self.technologies, start_time=start_time
            )
            state.store(self.state_path)

        # We write append all found cells to a CSV on disk
        als_cells_file = open(self.als_cells_path, 'a', newline='')
        als_cells = csv.DictWriter(als_cells_file, [
            'technology', 'mcc', 'mnc', 'tac', 'cell',
            'latitude', 'longitude', 'accuracy', 'reach', 'score',
            'from_technology', 'from_mcc', 'from_mnc', 'from_tac', 'from_cell'
        ])
        if state.index == 0:
            als_cells.writeheader()

        # Loop through the cells from the sample and request nearby cells using Apple's Location Service
        als_endpoint = AppleLocationService()

        for row in tqdm(sample.itertuples(), total=len(sample), unit='cells'):
            index: int = row[0]

            if index < state.index:
                continue

            for retry in range(0, 6):
                if retry == 5:
                    print(f'Giving up after 5 retries')
                    state.skipped.append(index)
                    break

                try:
                    technology = row.radio

                    # We query UMTS cells similar to LTE cells
                    if technology == 'UMTS':
                        technology = 'LTE'

                    new_cells = als_endpoint.request_cells(ALSCell(
                        technology=ALSTechnology[technology],
                        country=int(row.mcc),
                        network=int(row.net),
                        area=int(row.area),
                        cell=int(row.cell),
                        location=None,
                    ))
                except Exception as exception:
                    print(f'{state}: Exception while requesting data from ALS: {exception}')
                    continue

                try:
                    als_cells.writerows([self._cell_to_dict(csv_cell, row) for csv_cell in new_cells])

                    state.index = index + 1
                    state.store(self.state_path)
                except Exception as exception:
                    print(f'{state}: Exception while saving data to disk: {exception}')
                    continue

                break

        als_cells_file.close()

        print(f'Collected cell tower data')
        print(f'Successful requests: {self.size - len(state.skipped)}')
        print(f'Erroneous requests: {state.skipped}')
        print()

        print('Reading the collected data into memory...')
        als_cells_data_frame = pandas.read_csv(self.als_cells_path)

        print('== Collection (End) ==')

        return sample, als_cells_data_frame, state

    def _analyze_data(self, sample: pandas.DataFrame, als_cells: pandas.DataFrame, state: ExperimentState):
        """ Analyze the collected data and print the results. """
        print('== Analysis (Start) ==')

        state.phase = ExperimentPhase.ANALYZING
        state.index = 0
        state.store(self.state_path)

        # Read the full cell database and reduce it to the columns identifying cells in the selected country,
        # and rename the remaining cells the schema of the data frame apple_database.
        open_database = CSVCellDatabase(self.database_path, self.mcc).read()  # [['mcc', 'net', 'area', 'cell']]
        open_database = open_database.rename(columns={'net': 'mnc', 'area': 'tac'})

        # Find the percentage of cells that exist in open databases but not in Apple's database.
        # We limit this comparison to the cells that were part of the selected sample.
        notfound_cells: pandas.DataFrame = als_cells[
            (als_cells['mcc'] == als_cells['from_mcc']) &
            (als_cells['mnc'] == als_cells['from_mnc']) &
            (als_cells['tac'] == als_cells['from_tac']) &
            (als_cells['cell'] == als_cells['from_cell']) &
            (als_cells['accuracy'] < 0)
            ].drop_duplicates()
        notfound_count = len(notfound_cells.index)
        notfound_percentage = notfound_count / self.size
        print(f'{notfound_count} / {self.size} = {notfound_percentage:.2%} '
              f'of sample cells are not found in Apple\'s database')
        print()

        # Reduce the dataset to the columns identifying cells, remove duplications as well as
        # rough location approximations without a specific cell id (cell == -1), cells from neighbouring countries,
        # and invalid cells (accuracy == -1)
        apple_database = als_cells[als_cells['accuracy'] >= 0]
        apple_database = apple_database[['mcc', 'mnc', 'tac', 'cell', 'technology']].drop_duplicates()
        apple_database = apple_database.rename(columns={'technology': 'radio'})
        apple_database = apple_database[(apple_database['cell'] > 0) & (apple_database['mcc'].isin(self.mcc))]

        # Duplicate all LTE cell of ALS, because Apple bundles LTE & UMTS
        apple_merge_database = apple_database[apple_database['radio'] == 'LTE']\
            .replace(to_replace='LTE', value='UMTS')
        apple_merge_database = pandas.concat([apple_database, apple_merge_database])

        # Find the intersection of both datasets (open_database & sample of apple_database).
        intersection = pandas.merge(
            open_database, apple_merge_database, how='inner', on=['mcc', 'mnc', 'tac', 'cell', 'radio'])
        intersection = intersection.drop_duplicates(subset=['mcc', 'mnc', 'tac', 'cell', 'radio'])

        # Find the percentage of overlap between them from the point of the sample of Apple's database.
        intersection_percentage = len(intersection.index) / len(apple_database.index)
        print(f'Found {len(intersection.index)} / {len(apple_database)} = {intersection_percentage:.2%} '
              f'of Apple\'s cells in the open database')
        print()

        # Count the number of cells in Apple's DB grouped by their radio technology
        print('Cells grouped by radio technology which are found in Apple\'s databases:')
        print('(Notice that LTE & UMTS cells are grouped together as LTE)')
        print(apple_database.groupby(['radio'])['radio'].count())
        print()

        # Count the number of cells in the intersection grouped by their radio technology (in the open database)
        print('Cells grouped by radio technology which are found in both databases:')
        print(intersection.groupby(['radio'])['radio'].count())
        print()

        # Count the number of cells grouped by a network code & network operator tuple:
        # https://stackoverflow.com/a/68797863
        intersection_mnc = intersection[['mcc', 'mnc']] \
            .value_counts(subset=['mcc', 'mnc'], dropna=True) \
            .reset_index(name='open_count')

        apple_mnc = apple_database[['mcc', 'mnc']] \
            .value_counts(subset=['mcc', 'mnc'], dropna=True) \
            .reset_index(name='apple_count')
        # Merge the two dataframes with an outer join:
        mnc_dataframe = pandas.merge(intersection_mnc, apple_mnc, how='outer', on=['mcc', 'mnc'])
        # Fill missing values from the merge with 0 and convert the column back to the int datatype:
        # https://stackoverflow.com/a/49940609
        mnc_dataframe = mnc_dataframe.fillna(0).astype(int)
        # Compute the percentage of cells in the open database vs. in Apple's database (coverage)
        # for each network code & network operator tuple.
        mnc_dataframe['coverage'] = mnc_dataframe.apply(lambda x: x['open_count'] / x['apple_count'], axis=1)

        # Print the coverage as formatted percentage strings: https://stackoverflow.com/a/54110339
        mnc_dataframe['coverage'] = mnc_dataframe['coverage'].map("{:.2%}".format)
        print('Cells grouped by their network operator counted per database:')
        print(mnc_dataframe)

        state.phase = ExperimentPhase.FINISHED
        state.index = 0
        state.store(self.state_path)

        print('== Analysis (End) ==')

    def run(self):
        """ Run the whole experiment, first by collecting data and then analyzing it. """
        start_time = datetime.now()

        sample, als_cells, state = self._collect_data()
        self._analyze_data(sample, als_cells, state)

        end_time = datetime.now()
        print(f'Finished successfully, took {end_time - start_time}s')


def main():
    """ The main function responsible for parsing arguments and initializing the experiment class. """

    # Parse the arguments

    parser = argparse.ArgumentParser(description='Nearby Cell Experiment')
    technologies = ['CDMA', 'GSM', 'UMTS', 'LTE', 'NR']

    parser.add_argument(
        '-n', '--size', type=int, default=1000,
        help='Number of cell which are samples from the given dataset and requested from Apple.')
    # Parse hex values: https://stackoverflow.com/a/48950906
    parser.add_argument(
        '-s', '--seed', type=functools.wraps(int)(lambda x: int(x, 0)),
        help='A seed to influence the sampling of the database, resumes an experiment if its folder exists.'
    )
    # Source: https://en.wikipedia.org/wiki/Mobile_country_code
    parser.add_argument(
        '-mcc', '--mobile-country-code', type=str, default='262',
        help='Comma-seperated list of integers used to identify the cellular networks in a given country.')
    # Sources:
    # https://opencellid.org/downloads.php
    # https://location.services.mozilla.com/downloads
    parser.add_argument(
        '-d', '--database', type=Path, required=True,
        help='Path to a Mozilla Location Service- / OpenCellid-compliant database.')
    parser.add_argument(
        '-t', '--technologies', nargs='*', choices=technologies, type=str,
        help='Consider a subset of the available radio technologies for sampling.')
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Increase verbosity of the output.')

    # Check if the arguments are valid

    args = parser.parse_args()
    database_path: Path = args.database.absolute()

    mcc_str: str = args.mobile_country_code
    mcc = [int(mcc_element) for mcc_element in mcc_str.split(",")]

    if len(mcc) == 0:
        print(f'Provide at least one element for the \'-mcc\' argument')
        return

    if not database_path.exists() or not database_path.is_file():
        print(f'The given database path {database_path} does not point to a valid file')
        return

    if not database_path.suffix == '.csv':
        print(f'The given database path {database_path} is no csv file')
        return

    seed: int = args.seed
    if not seed:
        # If not set, generate a random seed
        seed = args.seed or random.randint(0, (2 ** 32) - 1)
    print(f'Seed: {hex(seed)}')

    # Run the experiment

    experiment = NearbyCellExperiment(
        size=args.size,
        mcc=mcc,
        database=database_path,
        verbose=args.verbose,
        technologies=args.technologies or technologies,
        seed=seed
    )

    experiment.run()


if __name__ == '__main__':
    main()
