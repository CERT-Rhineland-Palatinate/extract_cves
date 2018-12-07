# Extract CVEs from resource (file, url)

I was bored of copying and pasting CVE numbers. 
The script extracts all CVE numbers from a given resource (file or url).

## Getting Started

```
python3 extract_cves.py -h
```

## Examples

```
# Get CVEs from URL
python3 extract_cves.py -u https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html
python3 extract_cves.py -u https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
python3 extract_cves.py -u https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.34


# Get CVEs from file with verbose output
python3 extract_cves.py -v -f malformed_cves.txt

# Extended Check - every found and formal valid CVE is checked against the database
python3 extract_cves.py -v -f malformed_cves.txt

# Check one CVE
python3 extract_cves.py -c CVE-2018-0815
```

### Prerequisites

Python3 with the stdlib.

Mitre csv database when using the extended check.

(Can be downloaded for free at https://cve.mitre.org/data/downloads/allitems.csv.gz)

### Installing

The script has no other dependencies as Python3 with the stdlib. 

## Authors

* **@secw0tschel** - *Initial work* - (https://github.com/wotschel)

## License

This project is licensed under the MIT License.
