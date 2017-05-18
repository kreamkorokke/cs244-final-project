from scapy import all as scp
import argparse
import threading
from collections import deque
import time

class cc:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


MSS = 1500
RETRANSMIT_TIMEOUT = 1 # sec 
DUMMY_PAYLOAD = '*' * MSS
H1_ADDR = '10.0.0.1'
H1_PORT = 20001
H2_ADDR = '10.0.0.2'
H2_PORT = 20002

parser = argparse.ArgumentParser(description="Naive TCP.")
parser.add_argument('--role', dest='role', 
                    required=True,
                    help="The role of the TCP client (`sender` or `receiver`)")
parser.add_argument('--host', dest='host', 
                    required=True,
                    help="Mininet host (`h1` or `h2`)")

class TCP_Client:
    def __init__(self, role, host):
        self.seq = 0
        self.next_seq = 1
        self.ack = 1
        self.received_packets = deque()
        self.outstanding_segments = set()

        self.cwnd = 1 * MSS
        self.ssthresh = 64 * 1024  # 64KB
        self.dupack = 0
        self.state = "slow_start"
        # see [RFC 2988] on how the retransmission timer works
        self.retransmission_timer = None

        self.role = role  # sender or receiver
        self.log_cache = None

        if host == 'h1':
            self.src_ip = H1_ADDR
            self.dst_ip = H2_ADDR
            self.src_port = H1_PORT
            self.dst_port = H2_PORT

        if host == 'h2':
            self.src_ip = H2_ADDR
            self.dst_ip = H1_ADDR
            self.src_port = H2_PORT
            self.dst_port = H1_PORT

    def send(self):
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port, 
                           flags='', seq=self.next_seq) \
                 / (DUMMY_PAYLOAD)
        scp.send(packet, verbose=0)
        self.next_seq += MSS
        if self.retransmission_timer is None:
            self.retransmission_timer = time.time()
        print cc.OKBLUE + '(sent) data seq=%d:%d' % \
                (packet[scp.TCP].seq, packet[scp.TCP].seq + MSS - 1) \
                + cc.ENDC

    def resend(self, event):
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port, 
                           flags='', seq=self.seq + 1) \
                 / (DUMMY_PAYLOAD)
        self.retransmission_timer = time.time()
        scp.send(packet, verbose=0)
        print cc.WARNING + '(resent:%s) data seq=%d:%d' % \
                 (event, packet[scp.TCP].seq, packet[scp.TCP].seq + MSS - 1) \
                 + cc.ENDC

    def send_ack(self, ack_no):
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port, 
                           flags='A', ack=ack_no) 
        scp.send(packet, verbose=0)
        print cc.OKBLUE + '(sent) ack ack=%d' % ack_no + cc.ENDC

    def timeout(self):
        if self.retransmission_timer is None:
            return
        elif self.retransmission_timer + RETRANSMIT_TIMEOUT < time.time():
            # on timeout
            self.resend('timeout')
            self.state = "slow_start"
            self.ssthresh = self.cwnd / 2
            self.cwnd = 1 * MSS
            self.dupack = 0

    def receive(self):
        if len(self.received_packets) == 0:
            return
        pkt = self.received_packets.popleft()[0]
        # data packet received
        if pkt[scp.TCP].flags == 0:
            print cc.OKGREEN + '(received) data seq=%d:%d' % \
                    (pkt[scp.TCP].seq, pkt[scp.TCP].seq + MSS - 1) \
                    + cc.ENDC
            if pkt[scp.TCP].seq == self.ack:
                self.ack += MSS
                while self.ack in self.outstanding_segments:
                    self.outstanding_segments.remove(self.ack)
                    self.ack += MSS
            elif pkt[scp.TCP].seq > self.ack:
                # a future packet (queue it)
                self.outstanding_segments.add(pkt[scp.TCP].seq)
            self.send_ack(self.ack)
        # ack received
        elif pkt[scp.TCP].flags & 0x10:  # ACK
            print cc.OKGREEN + '(received) ack ack=:%d' % (pkt[scp.TCP].ack - 1) \
                    + cc.ENDC
            if pkt[scp.TCP].ack - 1 > self.seq:
                # new ack
                self.seq = pkt[scp.TCP].ack - 1
                self.retransmission_timer = time.time()  # restart timer
                if self.state == "slow_start":
                    self.cwnd += MSS
                elif self.state == "congestion_avoidance":
                    self.cwnd += MSS * MSS / self.cwnd
                elif self.state == "fast_recovery":
                    self.state = "congestion_avoidance"
                    self.cwnd = self.ssthresh
                self.dupack = 0
            else:
                # duplicate ack
                self.dupack += 1
                if self.state != "fast_recovery" and self.dupack == 3:
                    self.state = "fast_recovery"
                    self.ssthresh = self.cwnd / 2
                    self.cwnd = self.ssthresh + 3 * MSS
                    # retransmit missing packet
                    self.resend('triple-ack')
                
                elif self.state == "fast_recovery":
                    self.cwnd += MSS

    def log_status(self):
        out = '(log) state=%s cwnd=%d, ssthread=%d' % \
                (self.state, self.cwnd, self.ssthresh)
        if out != self.log_cache:
            print out
            self.log_cache = out

    def start_sender(self):
        f = open('cwnd.txt', 'w')
        start_time = time.time()
        last_log_time = 0
        while True:
            if self.state == "slow_start" and self.cwnd >= self.ssthresh:
                self.state = "congestion_avoidance"
            if self.next_seq - self.seq - 1 < self.cwnd:
                self.send()
            self.receive()
            self.timeout()
            self.log_status()

            # log cwnd to file
            ms = time.time() - start_time
            if ms > last_log_time + 0.01:
                f.write('%.3f,%d\n' % (ms, self.cwnd))
                last_log_time = ms

    def start_receiver(self):
        while True:
            self.receive()

    def listen(self):
        def match_packet(pkt):
            return (pkt.haslayer(scp.IP) \
                and pkt[scp.IP].src == self.dst_ip \
                and pkt[scp.IP].dst == self.src_ip \
                and pkt.haslayer(scp.TCP) \
                and pkt[scp.TCP].sport == self.dst_port \
                and pkt[scp.TCP].dport == self.src_port) \
                and pkt[scp.TCP].flags & 0x4 == 0   # ignore RST 
        def queue_packet(pkt):
            self.received_packets.append((pkt, time.time()))
        scp.sniff(lfilter=match_packet, prn=queue_packet)

    def start(self):
        listen_t = threading.Thread(target=self.listen)
        listen_t.start()
        if self.role == 'sender':
            self.start_sender()
        if self.role == 'receiver':
            self.start_receiver()

if __name__ == "__main__":
    args = parser.parse_args()
    tcp = TCP_Client(args.role, args.host)
    tcp.start()
