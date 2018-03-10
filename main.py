import os

if os.name == 'nt':
    import pydivert
elif os.name == "posix":
    from scapy.all import *
    from netfilterqueue import NetfilterQueue
else:
    print("Error: os not supported")
    raise NotImplementedError


def xor(data):
    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return bytes(data)


def win_main():
    with pydivert.WinDivert("tcp.DstPort == " + str(port) + " or tcp.SrcPort == " + str(port)) as w:
        print("[*] Waiting for data")
        for packet in w:
            # print(packet)
            if len(packet.payload) > 0:
                if packet.dst_port == port:
                    print("Client request: ", packet.payload)
                if packet.src_port == port:
                    print("Server traffic: ", packet.payload)
                packet.payload = xor(packet.payload)
                if packet.dst_port == port:
                    print("Client traffic: ", packet.payload)
                if packet.src_port == port:
                    print("Server Request: ", packet.payload)
            w.send(packet)
    w.close()


def scapy_process(packet):
    pkt = IP(packet.get_payload())

    data = bytes(pkt[TCP].payload)
    if len(data) > 0:
        if pkt[TCP].dport == port:
            print("Client traffic: ", data)
        if pkt[TCP].sport == port:
            print("Server request: ", data)

        data = xor(data)

        if pkt[TCP].dport == port:
            print("Client request: ", data)
        if pkt[TCP].sport == port:
            print("Server traffic: ", data)

        pkt[TCP].payload = data
        del pkt[IP].chksum  # No need to update IP checksum
        del pkt[TCP].chksum  # Force update TCP checksum
        pkt.show2()

        packet.set_payload(bytes(pkt))

    packet.accept()


def linux_main():
    if os.geteuid() != 0:
        print("Error: Must be run as root !")
        return

    # Activate nfqueue into iptables :
    os.system("iptables -I INPUT -p tcp --dport " + str(port) + " -j NFQUEUE --queue-num 42")
    os.system("iptables -I OUTPUT -p tcp --sport " + str(port) + " -j NFQUEUE --queue-num 42")

    nfqueue = NetfilterQueue()
    nfqueue.bind(42, scapy_process)
    try:
        print("[*] Waiting for data")
        nfqueue.run()
    except KeyboardInterrupt:
        print()

    # Restoring iptables
    os.system("iptables -D INPUT -p tcp --dport " + str(port) + " -j NFQUEUE --queue-num 42")
    os.system("iptables -D OUTPUT -p tcp --sport " + str(port) + " -j NFQUEUE --queue-num 42")

    print("Successfully shutdown")


if __name__ == '__main__':
    port = 1723
    key = "msqnbtjcfszoezjlfgd"
    key = bytearray(key.encode('utf-8'))

    print("key in use:", key)
    if os.name == 'nt':
        win_main()
    elif os.name == "posix":
        linux_main()
    else:
        print("Error: os not supported")
        raise NotImplementedError
