import matplotlib.pyplot as plt

X = []
Y = []

with open('cwnd.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        s1, s2 = line.split(',')
        X.append(float(s1))
        Y.append(float(s2) / 1024)

plt.plot(X, Y)
plt.xlim([0, max(X)])
plt.xlabel('Time (s)')
plt.ylabel('Congestion Window (kB)')
plt.show()

