# cs244-final-project
Koki Yoshida and Yanshu Hong's CS244 Final Project - TCP Congestion Control with a Misbehaving Receiver

To run Mininet with XTerm windows:
```
$ sudo mn --custom mn.py --topo MyTopo -x
```

Run sender on host h1:
```
$ python naive-tcp.py --role sender --host h1
```

Run receiver on host h2:
```
$ python naive-tcp.py --role receiver --host h2
```

The sender logs its cwnd size in `cwnd.txt` with 10ms interval.
Use `plot.py` to plot cwnd.
