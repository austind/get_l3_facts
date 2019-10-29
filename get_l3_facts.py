#!/usr/bin/env python3

import sys
import os
import argparse
import csv
import getpass
import ipaddress
import logging
import napalm


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
        help="Text file with list of IPs and/or FQDNs (one per line) to query",
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
        help="Full path to save CSV output to (default: l3_facts.csv)",
        dest="csv_path",
        default="l3_facts.csv",
    )
    parser.add_argument(
        "--loglevel", "-l", help="Log level verbosity. (default: info)", default="info"
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
    args = parser.parse_args()
    if args.input:
        if not os.path.exists(args.input):
            raise FileNotFoundError("File {} does not exist".format(args.input))
    if not args.username:
        username = getpass.getuser()
        args.username = input("Username [{}]: ".format(username)) or username
    if not args.password:
        args.password = getpass.getpass()
    if not args.secret:
        args.secret = getpass.getpass("Enable secret: ")
    if not (args.hosts or args.input):
        parser.error("No host input")
        return None
    return args


def arg_list(string):
    return string.split(",")


def open_device(host, driver, username, password, secret, ssh_config):
    """ Opens connection to host and returns NAPALM object """
    napalm_driver = napalm.get_network_driver(driver)
    device = napalm_driver(
        hostname=host,
        username=username,
        password=password,
        optional_args={"secret": secret, "ssh_config_file": ssh_config},
    )
    device.open()
    return device


def get_iface_facts(device):
    """ Returns formatted interface facts for a single device """
    ifaces = device.get_interfaces()
    ifaces_ip = device.get_interfaces_ip()
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
    log_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(log_level, int):
        raise ValueError("Invalid log level: {}".format(args.loglevel))
    log = logging.getLogger(__name__)
    log.setLevel(log_level)
    formatter = logging.Formatter("get_l3_facts - %(message)s")
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(formatter)
    log.addHandler(ch)

    results = []
    hosts = []
    if args.input:
        with open(args.input, "r") as f:
            hosts = f.read().splitlines()
    else:
        hosts = args.hosts

    for c, host in enumerate(hosts, 1):
        progress = "[{} / {}]".format(c, len(hosts))
        msg = "Opening connection to {}".format(host)
        log.info("{}: {}".format(progress, msg))
        device = open_device(
            host,
            args.driver,
            args.username,
            args.password,
            args.secret,
            args.ssh_config,
        )
        msg = "Getting interface facts"
        log.info("{}: {}".format(progress, msg))
        iface_facts = get_iface_facts(device)
        msg = "Found {} addresses".format(len(iface_facts))
        log.info("{}: {}".format(progress, msg))
        msg = "Closing connection to {}".format(host)
        log.info("{}: {}".format(progress, msg))
        device.close()
        results = results + iface_facts
    msg = "Found {} addresses total".format(len(results))
    log.info(msg)
    msg = "Saving results to {}".format(args.csv_path)
    log.info(msg)
    save_csv(args.csv_path, results)
    log.info("Done")


if __name__ == "__main__":
    main()
