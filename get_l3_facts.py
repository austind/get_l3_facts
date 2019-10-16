import napalm
import getpass
import argparse
import ipaddress
import pprint

parser = argparse.ArgumentParser(
    description="Retrieve L3 interface info from a network device"
)
parser.add_argument("--device", "-d", help="IP or FQDN of device", required=True)
parser.add_argument(
    "--username", "-u", help="Username", default=getpass.getuser())
parser.add_argument(
    "--password", "-p", help="Password", default=getpass.getpass())
parser.add_argument('--secret', '-s', help='Enable secret', default=getpass.getpass('Secret: '))
parser.add_argument('--output', '-o', help='Save as CSV to this path')
parser.add_argument(
    "--ssh-config",
    "-c",
    help="Pass this SSH config file to NAPALM",
    default="~/.ssh/config",
    dest="ssh_config",
)
args = parser.parse_args()

napalm_driver = napalm.get_network_driver('ios')
device = napalm_driver(
    hostname=args.device,
    username=args.username,
    password=args.password,
    optional_args={"ssh_config_file": args.ssh_config, 'secret': args.secret},
)

device.open()
ifaces = device.get_interfaces()
ifaces_ip = device.get_interfaces_ip()
output = []
for iface, attrs in ifaces.items():
    ip_attrs = ifaces_ip.get(iface)
    if ip_attrs:
        attrs.update(ifaces_ip.get(iface))
        ipv4 = attrs.get('ipv4')
        for address, prefix in ipv4.items():
            prefix_length = prefix.get('prefix_length')
            cidr = '{}/{}'.format(address, prefix)
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
pprint.pprint(output)
device.close()