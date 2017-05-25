# cs244-final-project
Koki Yoshida and Yanshu Hong's CS244 Final Project - TCP Congestion Control with a Misbehaving Receiver

To run Mininet with XTerm windows:
```
$ sudo mn --custom mn.py --topo mytopo --link tc -x
```

Run sender on host h1:
```
$ python naive_tcp.py --role sender --host h1
```

Run receiver on host h2:
```
$ python naive_tcp.py --role receiver --host h2
```

The sender logs its cwnd size in `cwnd.txt` with 20ms interval.
Use `plot.py` to plot cwnd.

## Attacker Commands:
To run ACK Division Attacker:
```
$ python ack_division_attacker.py --num-division 10 --host h2
```

To run DupACK Spoofing Attacker:
```
$ python dupack_spoofing_attacker.py --num-dupacks 1000 --host h2
```

To run Opmistic ACKing Attacker:
```
$ python optimistic_acking_attacker.py --ack-interval 10 --host h2
```
