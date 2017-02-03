import dpkt
import humanfriendly
import nids
import sys
import pandas as pd
import socket

ips = {}
ip_to_domain = {}

def handle_tcp_stream(tcp):
    end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
    ports = [80, 443]
    if tcp.addr[1][1] not in ports:
        return
    global ips
    if tcp.nids_state == nids.NIDS_JUST_EST:
        tcp.client.collect = 1
        tcp.server.collect = 1
    elif tcp.nids_state == nids.NIDS_DATA:
        tcp.discard(0)
    elif tcp.nids_state in end_states:
        ip = tcp.addr[1][0]
        ips.setdefault(ip, 0)
        ips[ip] += len(tcp.client.data[:tcp.client.count]) + len(tcp.server.data[:tcp.server.count])

def udp_callback(addrs, payload, pkt):
    if addrs[0][1] != 53:
        return
    dns = dpkt.dns.DNS(payload)
    global ip_to_domain
    for q in dns.qd:
        for a in dns.an:
            try:
                ip = socket.inet_ntoa(a.ip)
                ip_to_domain[ip] = a.name
            except AttributeError:
                pass
    return

def extract(pcap_file):
    global ip_to_domain
    global ips
    ips = {}
    ip_to_domain = {}

    nids.param("tcp_workarounds", 1)
    nids.param("scan_num_hosts", 0)          # disable portscan detection
    nids.chksum_ctl([('0.0.0.0/0', False)])  # disable checksumming
    nids.param("filename", pcap_file)
    nids.init()

    nids.register_tcp(handle_tcp_stream)
    nids.register_udp(udp_callback)

    try:
        nids.run()
    except Exception, e:
        print "Exception ", pcap_file + " ", e
        return

    data = []
    columns = ('name', 'bytes')
    for ip, byte in ips.iteritems():
        name = ip_to_domain.get(ip)
        if name is None:
            try:
                name, alias, addresslist = socket.gethostbyaddr(ip)
                name += ' (rDNS)'
            except socket.herror as e:
                name = ip

        data.append([str(name), byte])
    df = pd.DataFrame(data, columns=columns)
    df = df.groupby('name', as_index=False).sum()
    df = df.sort('bytes', ascending=False)
    df['human_bytes'] = df.apply(lambda row: humanfriendly.format_size(row['bytes']), axis=1)
    return df

if __name__ == "__main__":
    for f in sys.argv[1:]:
        print f
        df = extract(f)
        if df is not None:
             print df.head(10)
