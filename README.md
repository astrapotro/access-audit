# Access Audit

Access Audit is a fast access log analyzer written in GNU Awk.

The project was created to analyze Apache HTTP Server access logs in corporate environments, and its architecture has been designed to support additional log formats in future versions.

The main goals are:

- No external dependencies.
- GNU Awk 4.0 compatible (RHEL 7+).
- Fast (single-pass log processing).
- Easy to extend.
- Suitable for very large log files.

---

## Features

Current version:

- Apache Ejie's corporate log parser
- HTTP status statistics
- Top IPs
- Top URLs
- Top Hosts
- Top Searches
- Top User-Agent
- Response time statistics
- Bandwidth statistics
- Bot detection
- Attack detection
- User-Agent classification
- HTTP methods
- Referer analysis
- JSON export

Roadmap:

- Extension statistics
- HTML reports
- CSV export

...


---

## Requirements

- GNU Awk >= 4.0
- Bash

No additional packages are required.

---

## Usage

```bash
./access-audit access.log
./access-audit /my/Access/Directory
./access-audit access.log.tar.gz
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
0.2.1
```

This project is currently under active development.

