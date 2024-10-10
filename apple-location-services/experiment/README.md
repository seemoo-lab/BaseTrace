# Nearby Cells Experiment

An experiment comparing Apple's Location Service (ALS) database with open cell databases by 
sampling a number of cells from the open database and requesting nearby cells using ALS.
It is then checked if the nearby cells are included in the open database.

## Usage

First, download a CSV cell database in
the [Ichnaea format](https://ichnaea.readthedocs.io/en/latest/import_export.html):

* [Mozilla Location Service](https://location.services.mozilla.com/downloads)
* [OpenCellid](https://opencellid.org/downloads.php)

Next, choose a country which you want to research and find its mobile country code (mcc) from
[Wikipedia](https://de.wikipedia.org/wiki/Mobile_Country_Code).

In this example, we're picking 1000 random samples from the database `MLS-full-cell-export-2022-11-24T000000.csv`
They are used as request parameters for Apple's Location Service (ALS).
It answers with a number of neighbouring cells.
Then, we check how much of Apple's cells are contained in the open database and print the result as a percentage.
Furthermore, we group the results by mobile network operators.

The whole process should take around 15 minutes.

```bash
python3 ./nearby_cells.py -n 1000 -mcc 262 -d ./MLS-full-cell-export-2022-11-24T000000.csv
```

The seed parameter can be useful if you want to resume or repeat an experiment.
For example if the data collection was aborted midway, or you've improved the data analysis. 
Ensure that the experiment folder still exists and pass its seed as a parameter.

```bash
python3 ./nearby_cells.py -n 1000 -mcc 262 -d ./MLS-full-cell-export-2022-11-24T000000.csv -s 0x33
```

## Parameters

| Name   | Description           | References                                                                                                 | Required |
|--------|-----------------------|------------------------------------------------------------------------------------------------------------|----------|
| `-mcc` | Mobile Country Code   | [Wikipedia](https://de.wikipedia.org/wiki/Mobile_Country_Code)                                             | Yes      |
| `-d`   | Path to Cell Database | [MLS](https://location.services.mozilla.com/downloads), [OpenCellid](https://opencellid.org/downloads.php) | Yes      |
| `-n`   | Sample Size           | Number of samples which are checked                                                                        | Yes      |
| `-s`   | Sample Seed           | Repeat or resume experiments                                                                               | No       |
| `-v`   | Verbose               |                                                                                                            | No       |
| `-gsm` | Include GSM Cells     | Also consider GSM cells for sampling                                                                       | No       |
