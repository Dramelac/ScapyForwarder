import getopt
import os
import sys
import socket

if os.name == 'nt':
    import pydivert
    import ctypes
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
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        print("Error: Must be run as administrator !")
        return
    filterIp = ""
    if target is not None:
        filterIp = "(ip.SrcAddr == " + str(target) + " or ip.DstAddr == " + str(target) + ") and "
    filterIp += "(tcp.DstPort == " + str(port) + " or tcp.SrcPort == " + str(port) + ")"
    print(filterIp)
    with pydivert.WinDivert(filterIp) as w:
        try:
            if not mute:
                print("[*] Waiting for data")
            for packet in w:
                # print(packet)
                if len(packet.payload) > 0:
                    if (not mute) and packet.dst_port == port:
                        print("Client request: ", packet.payload)
                    if (not mute) and verbose and packet.src_port == port:
                        print("Server traffic: ", packet.payload)
                    packet.payload = xor(packet.payload)
                    if (not mute) and verbose and packet.dst_port == port:
                        print("Client traffic: ", packet.payload)
                    if (not mute) and packet.src_port == port:
                        print("Server Request: ", packet.payload)
                w.send(packet)
        except KeyboardInterrupt:
            if not mute:
                print("Shutdown...")
        w.close()


def scapy_process(packet):
    pkt = IP(packet.get_payload())

    data = bytes(pkt[TCP].payload)
    if len(data) > 0:
        if (not mute) and verbose and pkt[TCP].dport == port:
            print("Client traffic: ", data)
        if (not mute) and pkt[TCP].sport == port:
            print("Server request: ", data)

        data = xor(data)

        if (not mute) and pkt[TCP].dport == port:
            print("Client request: ", data)
        if (not mute) and verbose and pkt[TCP].sport == port:
            print("Server traffic: ", data)

        pkt[TCP].payload = data
        del pkt[IP].chksum  # No need to update IP checksum
        del pkt[TCP].chksum  # Force update TCP checksum
        # pkt.show2()

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
        if not mute:
            print("[*] Waiting for data")
        nfqueue.run()
    except KeyboardInterrupt:
        print()

    # Restoring iptables
    os.system("iptables -D INPUT -p tcp --dport " + str(port) + " -j NFQUEUE --queue-num 42")
    os.system("iptables -D OUTPUT -p tcp --sport " + str(port) + " -j NFQUEUE --queue-num 42")

    if not mute:
        print("Successfully shutdown")


def print_help():
    print("Help :", sys.argv[0])
    print("\t-h, --help\t\tPrint this help")
    print("\t-v, --verbose\t\tPrint traffic details")
    print("\t-m, --mute\t\tMute all traffic logs")
    print("\t-p, --port\t\tService port")
    print("\t-t, --target\t\tIP filter")


def params():
    global verbose, mute, port, target, key

    opts, args = getopt.getopt(sys.argv[1:], "hvmp:k:t:", ["help", "verbose", "mute", "port=", "target=", "key="])
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_help()
            sys.exit()
        elif opt in ("-v", "--verbose"):
            verbose = True
        elif opt in ("-m", "--mute"):
            mute = True
        elif opt in ("-p", "--port"):
            port = int(arg)
        elif opt in ("-t", "--target"):
            target = socket.gethostbyname(arg)
        elif opt in ("-k", "--key"):
            key = bytearray(arg.encode('utf-8'))


if __name__ == '__main__':
    # Default parameters
    port = 80
    key = "msqnbtjcfszoezjlfgd"
    key = bytearray(key.encode('utf-8'))
    verbose = False
    mute = False
    target = None

    params()

    if not mute:
        print("key in use:", key.decode("utf-8"))
    if os.name == 'nt':
        win_main()
    elif os.name == "posix":
        linux_main()
    else:
        print("Error: os not supported")
        raise NotImplementedError
