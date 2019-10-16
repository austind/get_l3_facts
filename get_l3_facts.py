import argparse
import csv
import napalm
import getpass
import ipaddress


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
        ip_attrs = ifaces_ip.get(iface)
        if ip_attrs:
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
        "description",
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output)


def main():
    """ Save L3 interface info from a collection of network devices to CSV. """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--hosts",
        "-H",
        help="Comma-delimited list of IPs and/or FQDNs to query",
        required=True,
        type=arg_list,
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

    # If we handle these defaults in argparse above, it will require a password no matter what,
    # even when dry-running with --help
    if not args.username:
        username = getpass.getuser()
        args.username = input("Username [{}]: ".format(username)) or username
    if not args.password:
        args.password = getpass.getpass()
    if not args.secret:
        args.secret = getpass.getpass("Enable secret: ")

    results = []
    for host in args.hosts:
        device = open_device(
            host,
            args.driver,
            args.username,
            args.password,
            args.secret,
            args.ssh_config,
        )
        iface_facts = get_iface_facts(device)
        device.close()
        results = results + iface_facts
    save_csv(args.csv_path, results)


if __name__ == "__main__":
    main()
