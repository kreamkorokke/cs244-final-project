import matplotlib.pyplot as plt

def read_lines(f, t, s):
    lines = f.readlines()[:-1]
    for line in lines:
        time, seq = line.split(',')
        t.append(float(time))
        s.append(float(seq))

normal_time, normal_seq = [], []
attack_time, attack_seq = [], []
normal = open('seq_num.txt', 'r')
attack = open('seq_num_attack.txt', 'r')

read_lines(normal, normal_time, normal_seq)
read_lines(attack, attack_time, attack_seq)

plt.plot(normal_time, normal_seq, 'r', label='Regular TCP')
plt.plot(attack_time, attack_seq, 'b--', label='TCP with Receiver Attack')
plt.legend(loc='upper left')
plt.xlim([0, max((max(normal_time), max(attack_time)))])
plt.ylim([0, max((max(normal_seq), max(attack_seq)))])
plt.xlabel('Time (s)')
plt.ylabel('Sequence Number (Bytes)')
plt.show()

normal.close()
attack.close()
