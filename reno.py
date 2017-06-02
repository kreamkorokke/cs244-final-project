# Suppresses Scapy runtime warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy import all as scp
import argparse
import threading
from collections import deque
import time
from color import cc

MSS = 1500
RETRANSMIT_TIMEOUT = 2.0  # sec
DUMMY_PAYLOAD = '*' * MSS
H1_ADDR = '10.0.0.1'
H1_PORT = 20001
H2_ADDR = '10.0.0.2'
H2_PORT = 20002

class TCP_Client:   
    def __init__(self, role, host, **kwargs):
        self.seq = 0
        self.next_seq = 1
        self.ack = 1
        self.received_packets = deque()
        self.outstanding_segments = set()

        self.cwnd = 1 * MSS
        self.ssthresh = 64 * 1024  # 64KB
        self.dupack = 0
        self.state = "slow_start"
        # see [RFC 6298] on how the retransmission timer works
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

        self.limit = None
        # stop the sender after seq_no exceeding this limit
        if role == 'sender':
            if 'limit' in kwargs:
                self.limit = kwargs['limit']
        # list of time logs for plotting
        self.seq_log, self.ack_log = [], []
        self.log_attacker = False
        # verbose flag
        self.verbose = kwargs['verbose']

    def send(self):
        if self.limit and self.next_seq > self.limit:
            return
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port, 
                           flags='', seq=self.next_seq) \
                 / (DUMMY_PAYLOAD)
        scp.send(packet, verbose=0)
        self.next_seq += MSS
        if self.retransmission_timer is None:
            self.retransmission_timer = time.time()
        self.xprint(cc.OKBLUE + '(sent) data seq=%d:%d' % \
                (packet[scp.TCP].seq, packet[scp.TCP].seq + MSS - 1) \
                + cc.ENDC)

    def resend(self, event):
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port, 
                           flags='', seq=self.seq + 1) \
                 / (DUMMY_PAYLOAD)
        self.retransmission_timer = time.time()
        scp.send(packet, verbose=0)
        self.xprint(cc.WARNING + '(resent:%s) data seq=%d:%d' % \
                 (event, packet[scp.TCP].seq, packet[scp.TCP].seq + MSS - 1) \
                 + cc.ENDC)

    def send_ack(self, ack_no):
        # update ack log
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port, 
                           flags='A', ack=ack_no) 
        scp.send(packet, verbose=0)
        self.ack_log.append((time.time() - self.base_time, ack_no))
        self.xprint(cc.OKBLUE + '(sent) ack ack=%d' % ack_no + cc.ENDC)

    def send_fin(self):
        packet = scp.IP(src=self.src_ip, dst=self.dst_ip) \
                 / scp.TCP(sport=self.src_port, dport=self.dst_port,
                           flags='F')
        scp.send(packet, verbose=0)
        if self.role == 'sender':
            msg = 'all data sent'
        else:
            msg = 'all data received'
        self.xprint(cc.OKBLUE + '(sent) fin [%s]' % msg + cc.ENDC)

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

    def post_receive(self, pkt, status):
        # called after a data segment is received
        # subclass overwrites this function to implement attacks
        self.send_ack(self.ack)

    def receive(self):
        if len(self.received_packets) == 0:
            return
        pkt = self.received_packets.popleft()[0]
        
        # data packet received
        if pkt[scp.TCP].flags == 0:
            # update seq log
            self.seq_log.append((time.time() - self.base_time, pkt[scp.TCP].seq))
            self.xprint(cc.OKGREEN + '(received) data seq=%d:%d' % \
                    (pkt[scp.TCP].seq, pkt[scp.TCP].seq + MSS - 1) \
                    + cc.ENDC)
            if pkt[scp.TCP].seq == self.ack:
                status = 'new'
                self.ack += MSS
                while self.ack in self.outstanding_segments:
                    self.outstanding_segments.remove(self.ack)
                    self.ack += MSS
            elif pkt[scp.TCP].seq > self.ack:
                # a future packet (queue it)
                status = 'future'
                self.outstanding_segments.add(pkt[scp.TCP].seq)
            else:
                status = 'duplicate'
            self.post_receive(pkt, status)
        # ack received
        elif pkt[scp.TCP].flags & 0x10:  # ACK
            self.xprint(cc.OKGREEN + '(received) ack ack=:%d' % \
                    (pkt[scp.TCP].ack - 1) \
                    + cc.ENDC)
            if pkt[scp.TCP].ack - 1 > self.seq:
                # new ack
                self.seq = pkt[scp.TCP].ack - 1
                """
                [RFC 6298]
                    (5.3) When an ACK is received that acknowledges new data, 
                restart the retransmission timer so that it will expire after 
                RTO seconds (for the current value of RTO).
                """
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
                """
                [RFC 5681]
                    On the first and second duplicate ACKs received at a 
                sender, a TCP SHOULD send a segment of previously unsent data 
                per [RFC 3042] provided that the receiver's advertised window 
                allows, the total Flight Size would remain less than or 
                equal to cwnd plus 2*SMSS, and that new data is available 
                for transmission.  Further, the TCP sender MUST NOT change 
                cwnd to reflect these two segments [RFC 3042].
                """
                if self.dupack < 3:
                    self.send()
                elif self.dupack == 3:
                    self.state = "fast_recovery"
                    self.ssthresh = self.cwnd / 2
                    self.cwnd = self.ssthresh + 3 * MSS
                    # retransmit missing packet
                    self.resend('triple-ack')
                elif self.state == "fast_recovery":
                    self.cwnd += MSS
        # fin received
        elif pkt[scp.TCP].flags & 0x1:  # FIN
            self.xprint(cc.OKGREEN + '(received) fin' + cc.ENDC)
            if self.role == 'sender' and self.state == 'fin_sent':
                return 'tear_down'
            if self.role == 'receiver':
                self.send_fin()
                return 'tear_down'

    def log_status(self):
        out = '(control:%s) cwnd=%d, ssthread=%d' % \
                (self.state, self.cwnd, self.ssthresh)
        if out != self.log_cache:
            self.xprint(out)
            self.log_cache = out

    def xprint(self, content):
        if not self.verbose: return
        timestamp = time.time() - self.base_time
        print cc.BOLD + '{:6.3f} '.format(timestamp) + cc.ENDC + content

    def start_sender(self):
        start_time = time.time()
        last_log_time = 0
        while True:
            if self.state == "slow_start" and self.cwnd >= self.ssthresh:
                self.state = "congestion_avoidance"
            if self.next_seq - self.seq - 1 < self.cwnd:
                self.send()
            if self.receive() == 'tear_down':
                self.state = 'tear_down'
                break
            if self.state != 'fin_sent':
                self.timeout()
            
            # send FIN when data sent over pre-specified limit
            if self.limit and self.seq >= self.limit:
                if self.state == 'fin_sent' \
                    and self.retransmission_timer + RETRANSMIT_TIMEOUT < time.time():
                    continue
                self.send_fin()
                self.retransmission_timer = 0
                self.state = 'fin_sent'
            
            self.log_status()

    def start_receiver(self):
        while True:
          if self.receive() == 'tear_down':
            self.state = 'tear_down'
            break

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
        def stop_packet(pkt):
            return pkt.haslayer(scp.TCP) \
                and pkt[scp.TCP].flags & 0x1 != 0   # FIN flag
        scp.sniff(lfilter=match_packet, 
                  prn=queue_packet, 
                  stop_filter=stop_packet)

    def write_logs_to_files(self):
        filename = 'attack_log.txt' if self.log_attacker else 'log.txt'
        f = open(filename, 'w')
        for time, seq in self.seq_log:
            f.write('%s,%.3f,%d\n' % ('seq', time, seq))
        for time, ack in self.ack_log:
            f.write('%s,%.3f,%d\n' % ('ack', time, ack))
        f.close()

    def start(self):
        listen_t = threading.Thread(target=self.listen)
        # set it to daemon so that it will be killed when the main thread
        # exits
        listen_t.daemon = True
        listen_t.start()

        self.base_time = time.time()
        self.xprint('connection started')
        if self.role == 'sender':
            self.start_sender()
        if self.role == 'receiver':
            self.start_receiver()

        self.xprint('connection terminated')
        if self.role == 'receiver':
            self.xprint('writing seq/ack logs to file ...')
            self.write_logs_to_files()
            self.xprint('writing logs done!')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Naive TCP.")
    parser.add_argument('--role', dest='role', 
                        required=True,
                        help="The role of the TCP client (`sender` or `receiver`)")
    parser.add_argument('--host', dest='host', 
                        required=True,
                        help="Mininet host (`h1` or `h2`)")
    parser.add_argument('--limit', dest='limit', type=int,
                        help="Limit the total amount of data to send (in kB).")
    parser.add_argument('--verbose', dest='verbose', action='store_true',
                        help="Verbose flag for TCP communication log.")
    args = parser.parse_args()
    
    kwargs = {}
    if args.limit is not None:
      kwargs['limit'] = args.limit * 1000
    kwargs['verbose'] = args.verbose

    tcp = TCP_Client(args.role, args.host, **kwargs)
    tcp.start()
