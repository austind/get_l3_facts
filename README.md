# get_l3_facts.py

Retrieves IPv4 layer 3 info from network devices, saving output to CSV

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)

Requires:
* Python 3.6+
* [`napalm`](https://github.com/napalm-automation/napalm)

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
* `description` - Interface description (if any)

## Usage

`python3 get_l3_facts.py -H router1,router2,10.216.46.1 -o l3_facts.csv`

Example output:

```
device,interface,address,prefix_length,cidr,netmask,network,description
router1,Vlan10,10.0.32.1,24,10.0.32.1/24,255.255.255.0,10.0.32.0/24,Mgmt
router1,Vlan15,10.0.34.1,23,10.0.34.1/23,255.255.254.0,10.0.34.0/23,Staff
router1,Vlan15,210.155.195.33,29,210.155.195.33/29,255.255.255.248,210.155.195.32/29,Staff
router1,Vlan15,210.155.195.17,29,210.155.195.17/29,255.255.255.248,210.155.195.16/29,Staff
router1,Vlan20,10.0.33.1,24,10.0.33.1/24,255.255.255.0,10.0.33.0/24,Cameras
router1,Vlan25,10.0.36.1,24,10.0.36.1/24,255.255.255.0,10.0.36.0/24,Lab1
router1,Vlan35,10.0.37.1,24,10.0.37.1/24,255.255.255.0,10.0.37.0/24,Lab2
router1,Vlan45,10.0.38.1,23,10.0.38.1/23,255.255.254.0,10.0.38.0/23,Students
router2,GigabitEthernet1/0/1,10.250.80.10,30,10.250.80.10/30,255.255.255.252,10.250.80.8/30,
router2,GigabitEthernet1/0/2,10.250.80.21,30,10.250.80.21/30,255.255.255.252,10.250.80.20/30,
router2,GigabitEthernet1/0/3,10.250.80.25,30,10.250.80.25/30,255.255.255.252,10.250.80.24/30,
10.216.46.1,Vlan10,10.216.46.1,23,10.216.46.1/23,255.255.254.0,10.216.46.0/23,LAN
10.216.46.1,GigabitEthernet0/3,10.250.80.26,30,10.250.80.26/30,255.255.255.252,10.250.80.24/30,UPLINK
```


