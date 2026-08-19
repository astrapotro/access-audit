# Access Audit

Access Audit is a fast access log analyzer written in GNU Awk.

The project was created to analyze Apache HTTP Server access logs in corporate environments, but its architecture has been designed to support additional log formats in future versions.

The main goals are:

- No external dependencies.
- GNU Awk 4.0 compatible (RHEL 7+).
- Fast (single-pass log processing).
- Easy to extend.
- Suitable for very large log files.

---

## Features

Current version:

- Apache corporate log parser
- HTTP status statistics
- Top IPs
- Top URLs
- Top Hosts
- Top User-Agent
- Response time statistics
- Bandwidth statistics

Roadmap:

- Referer analysis
- HTTP methods
- Extension statistics
- User-Agent classification
- Bot detection
- Attack detection
- HTML reports
- CSV export
- JSON export

---

## Requirements

- GNU Awk >= 4.0
- Bash

No additional packages are required.

---

## Usage

```bash
./access-audit access.log
```

Future options:

```bash
./access-audit --dynamic access.log
./access-audit --top 50 access.log
./access-audit --html report.html access.log
./access-audit --csv report.csv access.log
./access-audit --json report.json access.log
```

---

## Project status

Current version:

```
0.2.0
```

This project is currently under active development.

