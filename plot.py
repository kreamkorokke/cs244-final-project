import matplotlib.pyplot as plt

X = []
Y = []
Z = []

with open('cwnd.txt', 'r') as f:
    lines = f.readlines()[:-1]
    for line in lines:
        s1, s2, s3 = line.split(',')
        X.append(float(s1))
        Y.append(float(s2) / 1024)
        Z.append(float(s3) / 1024)

plt.plot(X, Y, 'r')
plt.plot(X, Z, 'b--')
plt.xlim([0, max(X)])
plt.ylim([0, max(Y)])
plt.xlabel('Time (s)')
plt.ylabel('Congestion Window (kB)')
plt.show()

