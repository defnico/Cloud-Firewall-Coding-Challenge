import bisect

# Convert an hex ip address to an integer.
def ip_address_to_int(ip_address):
    ip_bytes = ip_address.split(".")
    if (len(ip_bytes) != 4):
        print "Bad ip_address: " + ip_address
        return -1
    else:
        return pow(256, 3) * int(ip_bytes[0]) +  pow(256, 2) * int(ip_bytes[1]) + \
               256 * int(ip_bytes[2]) + int(ip_bytes[3])

# A range of IP address represented as integers in the range [start_ip,end_ip] .
class IpRange(object):
    # Construct the range given a string with an optional dash specifying the range.
    # If no dash is given then the range is a single value.
    def __init__(self, range_string):
        ips = range_string.split("-")
        if len(ips) == 1:
            self._start_ip = self._end_ip = ip_address_to_int(ips[0])
        elif len(ips) == 2:
            self._start_ip = ip_address_to_int(ips[0])
            self._end_ip = ip_address_to_int(ips[1])
        else:
            print "Bad ip range: " + range_string

    def contains(self, ip_address):
        return self._start_ip <= ip_address <= self._end_ip

# A list of ip ranges.
class IpRanges(object):
    def __init__(self, ip_range):
        self._ip_ranges = [ip_range]

    # Extend the ip ranges from another ip_range instance
    def extend(self, other):
        self._ip_ranges.extend(other._ip_ranges)

    # TODO: sort and merge ranges so that we can use binary search.
    def preprocess(self):
        return

    # Test if an ip_address (in integer format) is contained in one of the ranges.
    def contains(self, ip_address):
        # TODO: change this to binary search once preprocess is implemented.
        for r in self._ip_ranges:
            if r.contains(ip_address):
                return True
        return False

# A port range in the range [start_port,end_port]
class PortRange(object):
    # Construct the range given a string with an optional dash specifying the range.
    # If no dash is given then the range is a single value.
    def __init__(self, range_string):
        ports = range_string.split("-")
        if len(ports) == 1:
            self._start_port = self._end_port = int(ports[0])
        elif len(ports) == 2:
            self._start_port = int(ports[0])
            self._end_port = int(ports[1])
        else:
            print "Bad port range: " + range_string
            self._start_port = self._end_port = 0

    # Test if a port is in the port range.
    def contains(self, port):
        return self._start_port <= port <= self._end_port

    def __eq__(self, other):
        return self._start_port == other._start_port and self._end_port == other._end_port

# A PortRange with a list of IP Ranges associated with that port range.
class PortIpRanges(object):
    # Construct with the port_range and a single ip_range.
    def __init__(self, port_range, ip_range):
        self._port_range = port_range
        self._ip_ranges = IpRanges(ip_range)

    # Test if a port is in the port_range and the ip_address is in one of the associated ip ranges.
    def contains(self, port, ip_address):
        return self._port_range.contains(port) and self._ip_ranges.contains(ip_address)

    # Custom comparison operators needed for binary search.
    def __lt__(self, port):
        return self._port_range._start_port < port

    def __gt__(self, port):
        return self._port_range._start_port > port

    def __eq__(self, other):
        return self._port_range._start_port == other._port_range._start_port and \
               self._port_range._end_port == other._port_range._end_port

# The allowable addresses specified by a list of PortIpRanges.
class AllowedAddresses(object):
    def __init__(self):
        self._port_ip_ranges = []

    def add(self, port_ip_range):
        self._port_ip_ranges.append(port_ip_range)

    def preprocess(self):
        # Sort the port ranges by min port value.
        self._port_ip_ranges.sort(key=lambda self: self._port_range._start_port)

        # Merge ip_address for the same port range.
        # TODO: also create new port ranges where there is partial overlap.
        port_ip_ranges = []  # Create a temporary list without the duplicates.
        for r in self._port_ip_ranges:
            if len(port_ip_ranges) > 0 and (port_ip_ranges[-1] == r):
                port_ip_ranges[-1]._ip_ranges.extend(r._ip_ranges)
            else:
                port_ip_ranges.append(r)

        # Copy back the list with duplicate port ranges removed.
        self._port_ip_ranges = port_ip_ranges

    # Test if the port and ip_address is in any of the PortIpRanges.
    def contains(self, port, ip_address):
        # Use binary search to find the port range containing port.
        index = bisect.bisect(self._port_ip_ranges, port) - 1
        if index < 0:
            return False
        else:
            return self._port_ip_ranges[index].contains(port, ip_address_to_int(ip_address))

class Firewall(object):
    def __init__(self, csv_filename):
        # Create a dictionary from the 4 combinations of direction / protocol to allowed addresses.
        self._range_maps = {"inboundtcp": AllowedAddresses(), "inboundudp": AllowedAddresses(),
                           "outboundtcp": AllowedAddresses(), "outboundudp": AllowedAddresses()}

        # Read in ranges from the csv file and add to allowed addresses for the direction / protocol buckets.
        with open(csv_filename) as f:
            for line in f:
                params = line.strip('\n').split(",")
                print params
                port_range = PortRange(params[2])
                ip_range = IpRange(params[3])
                port_ip_ranges = PortIpRanges(port_range, IpRanges(ip_range))
                dir_protocol = params[0] + params[1]
                if dir_protocol in self._range_maps.keys():
                    self._range_maps[dir_protocol].add(port_ip_ranges)
                else:
                    print "Bad direction and/or protocol: " + params[0] + ":" + params[1]

        # Preprocess the dictionary entries to do linear search.
        for k, v in self._range_maps.items():
            v.preprocess()

    # Test if a packet should be accepted by checking if it is contained in the associated
    # direction/protocol container.
    def accept_packet(self, direction, protocol, port, ip_address):
        dir_protocol = direction + protocol
        if dir_protocol in self._range_maps.keys():
            return self._range_maps[dir_protocol].contains(port, ip_address)
        else:
            print "Bad direction and/or protocol: " + direction + ":" + protocol

if __name__ == "__main__":
    # Create the firewall object
    fw = Firewall('firewall.csv')
    print fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")  # matches first rule
    print fw.accept_packet("inbound", "tcp", 80, "192.168.1.3")  # matches second rule
    print fw.accept_packet("inbound", "tcp", 95, "192.168.1.2")  # matches third rule
    print fw.accept_packet("inbound", "udp", 53, "192.168.2.1")  # matches fifth rule
    print fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")  # matches fourth rule
    print fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")  # false
    print fw.accept_packet("inbound", "udp", 24, "52.12.48.92")  # false
    print fw.accept_packet("inbound", "tcp", 80, "192.168.1.4")  # false
