# get_l3_facts.py

Retrieves IPv4 layer 3 info from network devices, saving output to CSV

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)

Requires:
* Python 3.6+
* [`napalm`](https://github.com/napalm-automation/napalm)
* [`tqdm`](https://github.com/tqdm/tqdm)

## Overview

For each network device provided, `get_l3_facts.py` pulls info for all L3 interfaces, formats the results, and combines them into a single CSV.

Column schema:
* `hostname` - Hostname, FQDN, or IP provided
* `interface` - Interface name
* `address` - IPv4 address
* `prefix_length` - Network prefix bits
* `cidr` - IP address in CIDR notation: `address`/`prefix_length`
* `netmask` - Netmask formatted in dotted-decimal
* `network` - CIDR-notated network ID that the `address` resides within
* `is_enabled` - Whether or not the interface is administratively enabled (true/false)
* `is_up` - Whether or not the interface is up/up (true/false)
* `description` - Interface description (if any)

## Usage

The only required argument is `-H`, a comma-delimited list of hostnames, FQDNs, and/or IP addresses of devices to query.
All other arguments are either optional, inferred, or prompted at runtime.

### Example

```
$ python3 get_l3_facts.py -H router1,router2,10.216.46.1
Username [adecoup]:
Password:
Enable secret:
Progress: 100%|#########################################################################################################################| 3/3 [00:00<00:00, 6102.29Device/s]
```

Resulting CSV:

```
device,interface,address,prefix_length,cidr,netmask,network,is_enabled,is_up,description
router1,Vlan10,10.0.32.1,24,10.0.32.1/24,255.255.255.0,10.0.32.0/24,TRUE,TRUE,Mgmt
router1,Vlan15,10.0.34.1,23,10.0.34.1/23,255.255.254.0,10.0.34.0/23,TRUE,TRUE,Staff
router1,Vlan15,210.155.195.33,29,210.155.195.33/29,255.255.255.248,210.155.195.32/29,TRUE,TRUE,Staff
router1,Vlan15,210.155.195.17,29,210.155.195.17/29,255.255.255.248,210.155.195.16/29,TRUE,TRUE,Staff
router1,Vlan20,10.0.33.1,24,10.0.33.1/24,255.255.255.0,10.0.33.0/24,TRUE,TRUE,Cameras
router1,Vlan25,10.0.36.1,24,10.0.36.1/24,255.255.255.0,10.0.36.0/24,TRUE,TRUE,Lab1
router1,Vlan35,10.0.37.1,24,10.0.37.1/24,255.255.255.0,10.0.37.0/24,TRUE,TRUE,Lab2
router1,Vlan45,10.0.38.1,23,10.0.38.1/23,255.255.254.0,10.0.38.0/23,TRUE,TRUE,Students
router2,GigabitEthernet1/0/1,10.250.80.10,30,10.250.80.10/30,255.255.255.252,10.250.80.8/30,TRUE,TRUE,
router2,GigabitEthernet1/0/2,10.250.80.21,30,10.250.80.21/30,255.255.255.252,10.250.80.20/30,TRUE,TRUE,
router2,GigabitEthernet1/0/3,10.250.80.25,30,10.250.80.25/30,255.255.255.252,10.250.80.24/30,TRUE,TRUE,
10.216.46.1,Vlan10,10.216.46.1,23,10.216.46.1/23,255.255.254.0,10.216.46.0/23,LAN,TRUE,TRUE,
10.216.46.1,GigabitEthernet0/3,10.250.80.26,30,10.250.80.26/30,255.255.255.252,10.250.80.24/30,TRUE,TRUE,UPLINK
```

## Arguments

```
$ python3 get_l3_facts.py --help
usage: get_l3_facts.py [-h] (--hosts HOSTS | --input INPUT)
                       [--username USERNAME] [--password PASSWORD]
                       [--secret SECRET] [--output CSV_PATH] [--driver DRIVER]
                       [--ssh-config SSH_CONFIG] [--max-threads THREADS]
                       [--timeout TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  --hosts HOSTS, -H HOSTS
                        Comma-delimited list of IPs and/or FQDNs to query
  --input INPUT, -i INPUT
                        Text file with list of IPs and/or FQDNs to query (one
                        per line)
  --username USERNAME, -u USERNAME
                        Username to use when logging into HOSTS
  --password PASSWORD, -p PASSWORD
                        Password to use when logging into HOSTS
  --secret SECRET, -s SECRET
                        Enable secret to pass to NAPALM
  --output CSV_PATH, -o CSV_PATH
                        Full path to save CSV output to (default:
                        ./l3_facts.csv)
  --driver DRIVER       Network driver for NAPALM to use (default: ios)
  --ssh-config SSH_CONFIG, -c SSH_CONFIG
                        SSH config file for NAPALM to use (default:
                        ~/.ssh/config)
  --max-threads THREADS, -t THREADS
                        Maximum number of concurrent connections. (default:
                        Python version default)
```
