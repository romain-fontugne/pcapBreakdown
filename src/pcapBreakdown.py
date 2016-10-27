#!/usr/bin/env python

from sys import argv
import sys
import dpkt
import pcap
from collections import defaultdict
import numpy as np
from matplotlib import pylab as plt

def ecdf(d, **kwargs):
        a = np.array(sorted(d.items()))
        x = a[:,0]
        y = np.cumsum(a[:,1])/float(np.sum(a[:,1]))
        
        x = np.concatenate(([x[0]],x))
        y = np.concatenate(([0],y))
        plt.plot(x, y, **kwargs )


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print "usage: %s input.pcap [output]" % argv[0]
        exit(-1)

    if len(argv) > 2:
        outputFile = argv[2]
    else:
        outputFile = "pktSize.png"

    pc = pcap.pcap(argv[1])
    # pc.setfilter("not icmp")

    count= {"v4":defaultdict(int), "v6":defaultdict(int)}
    for ts, p in pc:
        e = dpkt.ethernet.Ethernet(p, data=None)

        if isinstance(e.data, dpkt.ip.IP):
            count["v4"][e.data.len] += 1
        elif isinstance(e.data, dpkt.ip6.IP6):
            count["v6"][e.data.plen] += 1

    # Plot the packet size distribution
    plt.figure(figsize=(5,4))
    for key, val in count.items():
        ecdf(val, label=key)

    plt.ylabel("CDF")
    plt.xlabel("Packet size")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig(outputFile)

