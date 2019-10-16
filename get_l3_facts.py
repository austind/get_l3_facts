import csv
import napalm
import getpass
import argparse
import ipaddress

def arg_list(string):
    return string.split(',')

def save_csv(csv_file, output):
    fieldnames = [
        'device',
        'interface',
        'address',
        'prefix_length',
        'cidr',
        'netmask',
        'network',
        'description',
    ]
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output)

def main():
    parser = argparse.ArgumentParser(
        description="Retrieve L3 interface info from a network device"
    )
    parser.add_argument("--device", "-d", help="IP or FQDN of device", required=True, type=arg_list)
    parser.add_argument(
        "--username", "-u", help="Username", default=getpass.getuser())
    parser.add_argument(
        "--password", "-p", help="Password", default=getpass.getpass())
    parser.add_argument('--secret', '-s', help='Enable secret', default=getpass.getpass('Secret: '))
    parser.add_argument('--output', '-o', help='Save as CSV to this path', required=True)
    parser.add_argument('--driver', help='NAPALM network driver to use', default='ios')
    parser.add_argument(
        "--ssh-config",
        "-c",
        help="Pass this SSH config file to NAPALM",
        default="~/.ssh/config",
        dest="ssh_config",
    )
    args = parser.parse_args()

    napalm_driver = napalm.get_network_driver(args.driver)
    device = napalm_driver(
        hostname=args.device[0],
        username=args.username,
        password=args.password,
        optional_args={"ssh_config_file": args.ssh_config, 'secret': args.secret},
    )
    device.open()
    ifaces = device.get_interfaces()
    ifaces_ip = device.get_interfaces_ip()
    device.close()
    output = []
    for iface, attrs in ifaces.items():
        ip_attrs = ifaces_ip.get(iface)
        if ip_attrs:
            attrs.update(ifaces_ip.get(iface))
            ipv4 = attrs.get('ipv4')
            for address, prefix in ipv4.items():
                prefix_length = prefix.get('prefix_length')
                cidr = '{}/{}'.format(address, prefix_length)
                addr = ipaddress.ip_interface(cidr)
                network = str(addr.network)
                netmask = str(addr.netmask)
                output.append({
                    'device': args.device,
                    'interface': iface,
                    'description': attrs.get('description'),
                    'address': address,
                    'prefix_length': prefix_length,
                    'cidr': cidr,
                    'network': network,
                    'netmask': netmask,
                })
    print('Found {} L3 interfaces on {}'.format(len(ifaces_ip), args.device))
    save_csv(args.output, output)

if __name__ == '__main__':
    main()