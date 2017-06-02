import mn
import argparse
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections

OUTPUT_DIR = './plots'

def build_parser():
    parser = argparse.ArgumentParser(description="Attack plot generator")
    parser.add_argument('--output', dest='output_dir', default=OUTPUT_DIR,
                        help="Directory to store output plots.")
    parser.add_argument('--delay', dest='link_delay',
                        type=int, default=250,
                        help="Link delay in ms (default is 250ms).")
    parser.add_argument('--data-size', dest='data_size',
                        type=int, default=60,
                        help="Amount of data to be sent from sender side (in kB).")
    parser.add_argument('--num-attack', dest='num_attack',
                        type=int, default=50,
                        help="Number of ACK packets to perform attacks.")
    parser.add_argument('--opt-interval', dest='opt_interval',
                        type=int, default=20,
                        help="Time interval between sending optimistic ACKs\
                              in ms (used in Optimistic ACKing attack only).")
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Build topology
    topo = mn.StandardTopo(args.link_delay)
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    # Dumps network topology
    dumpNodeConnections(net.hosts)
    # Performs a basic all pairs ping test to check connectivity
    net.pingAll()
    
    # Note: for the following TCP communication,
    #       always start the receiver side first!
    data_size, num_attack = args.data_size, args.num_attack
    opt_interval, output_dir = args.opt_interval, args.output_dir
    h1 = net.get('h1')
    h2 = net.get('h2')

    # First, record a normal TCP communication
    print('Starting normal TCP connection...')
    h2.sendCmd('python reno.py --role receiver --host h2')
    h1.cmd('python reno.py --role sender --host h1 --limit %d'\
              % data_size)
    # Blocks execution until h2 has finished
    h2.waitOutput()
    print('Normal TCP connection done!')
    
    # ACK Division attack plot
    print('Starting ACK Division attack...')
    h2.sendCmd('python attacker.py --host h2 --attack div --num %d' % num_attack)
    h1.cmd('python reno.py --role sender --host h1 --limit %d' % data_size)
    h2.waitOutput()
    h2.cmd('mv attack_log.txt div_attack_log.txt')
    print('ACK Division attack done!')
    
    # DupACK Spoofing attack plot
    print('Starting DupACK Spoofing attack...')
    h2.sendCmd('python attacker.py --host h2 --attack dup --num %d' % num_attack)
    h1.cmd('python reno.py --role sender --host h1 --limit %d' % data_size)
    h2.waitOutput()
    h2.cmd('mv attack_log.txt dup_attack_log.txt')
    print('DupACK Spoofing attack done!')
    
    # Optimistic ACKing attack plot
    print('Starting Optimistic ACKing attack...')
    h2.sendCmd('python attacker.py --host h2 --attack opt --num %d --interval %d'\
                % (num_attack, opt_interval))
    text1 = h1.cmd('python reno.py --role sender --host h1 --limit %d' % data_size)
    text2 = h2.waitOutput()
    h2.cmd('mv attack_log.txt opt_attack_log.txt')
    print('Optimistic ACKing attack done!')

    # Shutdown mininet
    net.stop()

if __name__ == "__main__":
    main()
