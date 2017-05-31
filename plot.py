import os
import matplotlib.pyplot as plt
import argparse
from naive_tcp import check_bool
from attacker import check_attack_type

IMG_DIR = "./plots"

def read_lines(f, t, s):
    lines = f.readlines()[:-1]
    for line in lines:
        time, seq = line.split(',')
        t.append(float(time))
        s.append(float(seq))

def main():
    parser = argparse.ArgumentParser(description="Plot script for plotting sequence numbers.")
    parser.add_argument('--save', dest='save_imgs',
                        nargs='?', const=False, type=check_bool,
                        help="Set this to true to save images under %s." % IMG_DIR)
    parser.add_argument('--attack', dest='attack',
                        nargs='?', const="", type=check_attack_type,
                        help="Attack name (used in plot names).")
    args = parser.parse_args()
    save_imgs = args.save_imgs
    attack_name = args.attack

    if save_imgs and attack_name not in ['div', 'dup', 'opt'] :
        print("Attack name needed for saving plot figures.")
        return

    normal_time, normal_seq = [], []
    attack_time, attack_seq = [], []
    normal = open('seq_num.txt', 'r')
    attack = open('seq_num_attack.txt', 'r')
    
    read_lines(normal, normal_time, normal_seq)
    read_lines(attack, attack_time, attack_seq)
   
    if attack_name == 'div':
        attack_desc = 'ACK Division'
    elif attack_name == 'dup':
        attack_desc = 'DupACK Spoofing'
    else:
        attack_desc = 'Optimistic ACKing'
    plt.plot(normal_time, normal_seq, 'r', label='Regular TCP')
    plt.plot(attack_time, attack_seq, 'b--', label='TCP with %s Attack' % attack_desc)
    plt.legend(loc='upper left')
    plt.xlim([0, max((max(normal_time), max(attack_time)))])
    plt.ylim([0, max((max(normal_seq), max(attack_seq)))])
    plt.xlabel('Time (s)')
    plt.ylabel('Sequence Number (Bytes)')

    if save_imgs:
        # Save images to figure/
        if not os.path.exists(IMG_DIR):
            os.makedirs(IMG_DIR)
        plt.savefig(IMG_DIR + "/" + attack_name)
    else:
        plt.show()
    
    normal.close()
    attack.close()


if __name__ == "__main__":
    main()
