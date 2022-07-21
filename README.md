# Get CVSSv3 Vectors
A utility to pull CVSSv3 data from the NIST National Vulnerability Database

## Usage
Use `python port_scanner.py -h` to get a full list of arguments

```
usage: get_cvss_vectors.py [-h] (-c CVE_ID | -f CVE_LIST)

Request CVE details from National Vulnerability Database

optional arguments:
  -h, --help            show this help message and exit
  -c CVE_ID, --cve-id CVE_ID
                        Specify the requested CVE
  -f CVE_LIST, --cve-list CVE_LIST
                        Specify the requested CVEs from a list file (one CVE entry per line)
```

## Sources
This product uses data from the NVD API but is not endorsed or certified by the NVD.

Byers, Robert , Turner, Chris , Brewer, Tanya (2022), National Vulnerability Database, National Institute of Standards and Technology, https://doi.org/10.18434/M3436 (Accessed 2022-07-21)