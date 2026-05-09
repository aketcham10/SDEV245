# Secret Scanner

A simple Python CLI tool for scanning files and directories for common patterns that may indicate hardcoded secrets.

## Features

- Scan a file or directory recursively
- Detect likely secret patterns using regular expressions
- Report findings with filename, line number, and matched text
- Verbose logging with `--verbose`
- Optional report output file

## Installation

This tool is a standalone Python script. It requires Python 3.8+.

```bash
python secret_scanner.py /path/to/target
```

## Usage

```bash
python secret_scanner.py <path>
```

Options:

- `<path>`: file or directory to scan
- `-o`, `--output`: write findings to a report file
- `-v`, `--verbose`: enable verbose logging
- `-p`, `--progress`: show progress when scanning directories

Example:

```bash
python secret_scanner.py ./project -v -p
python secret_scanner.py ./project -o findings.csv
```

## Detection Logic

The scanner uses regular expressions to identify potential sensitive values in text files. The current patterns include:

- `AWS Access Key`: values that start with `AKIA` followed by 16 uppercase alphanumeric characters
- `AWS Secret Key`: common AWS secret key assignment forms
- `Generic API Key`: variable names such as `api_key`, `apikey`, `token`, `client_secret`, plus a value pattern
- `Generic Password`: common password variable names with a likely password assignment
- `Private Key Block`: PEM private key blocks such as `-----BEGIN PRIVATE KEY-----`
- `JWT Token`: JWT-like three-part base64-like string
- `Slack Token`: Slack token prefixes like `xoxb-`, `xoxa-`, etc.
- `Private Key File Reference`: common SSH and certificate markers

## Output

When secrets are found, the tool prints a CSV-style report with the following columns:

- `filename`
- `line`
- `pattern`
- `match`

If no findings are detected, the tool prints:

```
No likely hardcoded secrets detected.
```

## Notes and Limitations

- This tool uses heuristic regular expressions and may produce false positives.
- It is designed for text-based source files and skips files that appear to contain binary data.
- Manual review is recommended for any reported findings.

## License

This repository is released under the MIT License.
