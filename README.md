# cs244-final-project
Koki Yoshida and Yanshu Hong's CS244 Final Project - TCP Congestion Control with a Misbehaving Receiver

To run Mininet with XTerm windows (for TCP sawtooth):
```
$ sudo mn --custom mn.py --topo congestion --link tc -x
```
for attacks:
```
$ sudo mn --custom mn.py --topo standard --link tc -x
```

Run sender on host h1:
```
$ python naive_tcp.py --role sender --host h1
```
with limit (say, up to 60 kB of data):
```
$ python naive_tcp.py --role sender --host h1 --limit 60
```

Run receiver on host h2:
```
$ python naive_tcp.py --role receiver --host h2
```

## Attacker Commands:
To run ACK Division Attacker:
```
$ python attacker.py --attack div --num 50 --host h2
```

To run DupACK Spoofing Attacker:
```
$ python attacker.py --attack dup --num 50 --host h2
```

To run Optimistic ACKing Attacker:
```
$ python attacker.py --attack opt --num 50 --interval 10 --host h2
```

