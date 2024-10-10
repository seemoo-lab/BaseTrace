import argparse
from pathlib import Path

import pandas
import pandas as pd
from matplotlib import pyplot


def main():
    """ The main function parses arguments and determines the size of the given database. """

    parser = argparse.ArgumentParser(description='Database Size')
    parser.add_argument(
        '-d', '--database', type=Path, required=True,
        help='Path to a Mozilla Location Service- / OpenCelliD-compliant database.')

    args = parser.parse_args()
    database_path: Path = args.database.absolute()

    if not database_path.exists() or not database_path.is_file():
        print(f'The given database path {database_path} does not point to a valid file')
        return

    if not database_path.suffix == '.csv':
        print(f'The given database path {database_path} is no csv file')
        return

    print('Reading database...')
    df = pandas.read_csv(database_path)

    print()
    print('Count cells by RAT:')
    # https://sparkbyexamples.com/pandas/pandas-groupby-count-examples/
    print(df.groupby(['radio'])['radio'].count().sort_values().to_string())
    print()

    countries = {
        'USA': [310, 311, 312, 313, 314, 315, 316],
        'Germany': [262],
        'South Korea': [450],
        'Japan': [440],
        'India': [404],
    }
    for country, mcc in countries.items():
        print(f'Count cells by RAT for {country}:')
        print(df[df['mcc'].isin(mcc)].groupby(['radio'])['radio'].count().sort_values().to_string())
        print()

    print()
    print('Count cells by MCC:')
    # https://sparkbyexamples.com/pandas/pandas-groupby-count-examples/
    print(df.groupby(['mcc'])['mcc'].count().sort_values().to_string())

    print()
    print('Cells per Year:')
    # https://stackoverflow.com/a/19231939
    time_series = pd.to_datetime(df['updated'], unit='s')
    # https://stackoverflow.com/a/29036738
    year_count = time_series.groupby([time_series.dt.year]).count()
    print(year_count)
    year_count.plot(kind='bar')
    # https://stackoverflow.com/a/46965602
    pyplot.show()

    print()
    print(f'Total: {len(df.index)}')


if __name__ == '__main__':
    main()
