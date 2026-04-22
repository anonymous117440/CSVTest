# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a data-only repository containing a single CSV file (`test.csv`). There is no source code, build system, or test framework.

## Data File

**`test.csv`** — A tab-delimited file with 33 rows of IP address data. Format:
```
<sequential_number>\t<ip_address>
```

Example:
```
1	185.117.73.211
2	107.148.200.130
```

The file uses tab (`\t`) as a delimiter, not commas, despite the `.csv` extension.
