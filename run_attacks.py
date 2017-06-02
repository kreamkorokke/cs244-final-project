import mn
import argparse
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
import time

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
    drop_rate = net.pingAll()
    if drop_rate > 0:
        print 'Reachability test failed!! Please restart. '
        return

    # Note: for the following TCP communication,
    #       always start the receiver side first!
    data_size, num_attack = args.data_size, args.num_attack
    opt_interval, output_dir = args.opt_interval, args.output_dir
    h1 = net.get('h1')
    h2 = net.get('h2')

    # RTT = 4 * link_delay
    rtt = 4 * args.link_delay
    print('Round-trip delay is %.1f secs.' % (rtt / 1000.))

    # sleep 2s to clean up packets in the network
    time.sleep(2.)

    # First, record a normal TCP communication
    print('Starting normal TCP connection...')
    start_time = time.time()
    h2.sendCmd('python reno.py --role receiver --host h2')
    h1.sendCmd('python reno.py --role sender --host h1 --rtt %d --limit %d'\
                % (rtt, data_size))
    h2.waitOutput()
    h1.waitOutput()
    print('Normal TCP connection done! (%.2f sec)' % (time.time() - start_time))
    
    time.sleep(2.)

    # ACK Division attack plot
    print('Starting ACK Division attack...')
    start_time = time.time()
    h2.sendCmd('python attacker.py --host h2 --attack div --num %d' % num_attack)
    h1.sendCmd('python reno.py --role sender --host h1 --rtt %d --limit %d'\
                % (rtt, data_size))
    h2.waitOutput()
    h1.waitOutput()
    h2.cmd('mv attack_log.txt div_attack_log.txt')
    print('ACK Division attack done! (%.2f sec)' % (time.time() - start_time))
    
    time.sleep(2.)

    # DupACK Spoofing attack plot
    print('Starting DupACK Spoofing attack...')
    start_time = time.time()
    h2.sendCmd('python attacker.py --host h2 --attack dup --num %d' % num_attack)
    h1.sendCmd('python reno.py --role sender --host h1 --rtt %d --limit %d'\
                % (rtt, data_size))
    h2.waitOutput()
    h1.waitOutput()
    h2.cmd('mv attack_log.txt dup_attack_log.txt')
    print('DupACK Spoofing attack done! (%.2f sec)' % (time.time() - start_time))
   
    time.sleep(2.)

    # Optimistic ACKing attack plot
    print('Starting Optimistic ACKing attack...')
    start_time = time.time()
    h2.sendCmd('python attacker.py --host h2 --attack opt --num %d --interval %d'\
                % (num_attack, opt_interval))
    h1.sendCmd('python reno.py --role sender --host h1 --rtt %d --limit %d'\
                % (rtt, data_size))
    h2.waitOutput()
    h1.waitOutput()
    h2.cmd('mv attack_log.txt opt_attack_log.txt')
    print('Optimistic ACKing attack done! (%.2f sec)' % (time.time() - start_time))

    # Shutdown mininet
    net.stop()

if __name__ == "__main__":
    main()
