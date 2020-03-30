#!/usr/bin/env python3

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor
import getpass
import ipaddress
import napalm
import os
import tqdm


def get_args():
    """
    Function to gather all of the needed arguments
    Returns supplied args
    """
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--hosts",
        "-H",
        help="Comma-delimited list of IPs and/or FQDNs to query",
        type=arg_list,
    )
    group.add_argument(
        "--input",
        "-i",
        help="Text file with list of IPs and/or FQDNs to query (one per line)",
        type=str,
    )
    parser.add_argument(
        "--username", "-u", help="Username to use when logging into HOSTS"
    )
    parser.add_argument(
        "--password", "-p", help="Password to use when logging into HOSTS"
    )
    parser.add_argument("--secret", "-s", help="Enable secret to pass to NAPALM")
    parser.add_argument(
        "--output",
        "-o",
        help="Full path to save CSV output to (default: ./l3_facts.csv)",
        dest="csv_path",
        default="./l3_facts.csv",
    )
    parser.add_argument(
        "--driver",
        help="Network driver for NAPALM to use (default: ios)",
        default="ios",
    )
    parser.add_argument(
        "--ssh-config",
        "-c",
        help="SSH config file for NAPALM to use (default: ~/.ssh/config)",
        default="~/.ssh/config",
        dest="ssh_config",
    )
    parser.add_argument(
        "--max-threads",
        "-t",
        help="Maximum number of concurrent connections. (default: Python version default)",
        default=None,
        dest="threads",
    )
    parser.add_argument(
        "--timeout",
        "-T",
        help="Connection timeout (sec) to pass to NAPALM. (default: 120s)",
        default=120
        dest="timeout"
    args = parser.parse_args()
    if args.input:
        if not os.path.exists(args.input):
            raise FileNotFoundError(f"File {args.input} does not exist")
    if not args.username:
        username = getpass.getuser()
        args.username = input(f"Username [{username}]: ") or username
    if not args.password:
        args.password = getpass.getpass()
    if not args.secret:
        args.secret = getpass.getpass("Enable secret: ")
    if not (args.hosts or args.input):
        parser.error("No host input, cannot continue. Must provide either --hosts or --input.")
        exit(1)
    return args


def arg_list(string):
    return string.split(",")


def open_device(host, driver, username, password, secret, timeout, ssh_config):
    """ Opens connection to host and returns NAPALM object """
    napalm_driver = napalm.get_network_driver(driver)
    device = napalm_driver(
        hostname=host,
        username=username,
        password=password,
        timeout=timeout,
        optional_args={"secret": secret, "ssh_config_file": ssh_config},
    )
    device.open()
    return device


def get_iface_facts(host, args):
    """ Returns formatted interface facts for a single device """
    device = open_device(
        host, args.driver, args.username, args.password, args.secret, args.timeout, args.ssh_config
    )
    ifaces = device.get_interfaces()
    ifaces_ip = device.get_interfaces_ip()
    device.close()
    results = []
    for iface, attrs in ifaces.items():
        if ifaces_ip.get(iface):
            attrs.update(ifaces_ip.get(iface))
            ipv4 = attrs.get("ipv4")
            for address, prefix in ipv4.items():
                prefix_length = prefix.get("prefix_length")
                cidr = "{}/{}".format(address, prefix_length)
                addr = ipaddress.ip_interface(cidr)
                network = str(addr.network)
                netmask = str(addr.netmask)
                results.append(
                    {
                        "hostname": device.hostname,
                        "interface": iface,
                        "description": attrs.get("description"),
                        "address": address,
                        "prefix_length": prefix_length,
                        "cidr": cidr,
                        "network": network,
                        "netmask": netmask,
                        "is_enabled": attrs.get("is_enabled"),
                        "is_up": attrs.get("is_up"),
                    }
                )
    return results


def save_csv(csv_path, output):
    """ Saves output to CSV """
    fieldnames = [
        "hostname",
        "interface",
        "address",
        "prefix_length",
        "cidr",
        "netmask",
        "network",
        "is_enabled",
        "is_up",
        "description",
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output)


def main():
    """ Save L3 interface info from a collection of network devices to CSV. """
    args = get_args()
    results = []
    hosts = []
    if args.input:
        with open(args.input, "r") as f:
            hosts = f.read().splitlines()
    else:
        hosts = args.hosts

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        threads = []
        for host in hosts:
            threads.append(pool.submit(get_iface_facts, host, args))

    for thread in tqdm.tqdm(threads, desc="Progress", unit="Device", ascii=True):
        results = results + thread.result()

    save_csv(args.csv_path, results)


if __name__ == "__main__":
    main()
