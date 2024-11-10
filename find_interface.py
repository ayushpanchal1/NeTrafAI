from scapy.all import conf

# List all available interfaces
interfaces = conf.ifaces
for iface in interfaces:
    print(iface)