# cs244-final-project
Koki Yoshida and Yanshu Hong's CS244 Final Project 
- TCP Congestion Control with a Misbehaving Receiver


## One-line Reproduction
We have provided one single shell script that reproduces all three attacks
in one run. To reproduce the results, run:
```
$ sudo ./run.sh
```

The default network topology consists of two end hosts connected via one
switch. Default link delay is 375ms, which amounts to a round-trip delay of
1.5s. The whole process takes about 1 minute to run.

After the shell script finishes, check out the reproduced plots in the `./plot`
directory.


## TCP Reno Client Commands:
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
$ python reno.py --role sender --host h1
```
with limit (say, up to 60 kB of data):
```
$ python reno.py --role sender --host h1 --limit 60
```

Run receiver on host h2:
```
$ python reno.py --role receiver --host h2
```

Run sender/receiver with defense mechanisms (nonce layer) on:
```
$ python reno_enhanced.py --role sender --host h1
# python reno_enhanced.py --role receiver --host h2
```

Use `--verbose` to log all sent and received packets in the terminal window.


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

