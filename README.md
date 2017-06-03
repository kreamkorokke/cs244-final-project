# CS 244 Final Project
_CS 244 Final Project (Spring 17')_

Reproducing __Savage, Stefan, et al. "TCP congestion control with a misbehaving receiver."__ (SIGCOMM 99')

Koki Yoshida and Yanshu Hong


## One-line Reproduction
We have provided one single shell script that reproduces all three attacks
in one run. To reproduce the results, follow the following steps:

1. Download the VM image for CS 244 Assignment 1 (http://web.stanford.edu/class/cs244/vm/cs244-vm.ova). This VM image comes with Mininet and Scapy installed, which our code requires.

2. Load the VM image. Log in with username "cs244" and password "cs244". Please use the terminal in the VM. (SSH login might cause the plot script to break.)

3. Clone the Git Repo.  
```
$ mkdir project
$ git clone https://github.com/kreamkorokke/cs244-final-project.git project
$ cd project
```

4. Run the one-line shell (with __sudo__). 
```
$ sudo ./run.sh
```
The default network topology consists of two end hosts connected via one
switch. Default link delay for each link is 375ms, which amounts to a total round-trip delay of 1.5s. The whole process takes about 1 minute to run.

5. After the shell script finishes, check out the reproduced plots in the `./plot` directory. There are three plots generated, "div.png", "dup.png" and "opt.png", corresponding to ACK division, DupACK spoofing, and Optimistic ACKing attacks, respectively.


## Customizations
Several parameters related to the attack are customizable. Add flags in `run.sh` after `python run_attack.py` to explore.

Use `--delay` to specify per link delay in ms. The value we use in our reproduction is 375ms. Remember that an estimated round-trip delay is 4 times this per link delay. Because Scapy (a _Python_ package) is slow (it takes around 40ms to send one packet), use a higher link delay to see more evident attack outcomes.

Use `--data-size` to specify the total amount of data to send before tearing down the connection (in kB). We use 60kB as specified in the paper. Note that the default ssthread for TCP is 64kB. The attacks are most effective before TCP switches to congestion avoidance. Moreover, since our implementation for DupACK spoofing and Optimistic ACKing attacks only sends ACK flood on the first received data segment. The attack might not last long enough to let the sender send all data in one shot.

See the section on "Attack Commands" for flags `--num-attack` (equivalent to `--num`) and `--opt-interval` (equivalent to `--interval`).


## TCP Reno Client Commands
We built our own TCP Client (Reno) with Scapy in Python. To see the attack in live, you can run `reno.py` and `attacker.py` in Mininet XTerms.

To run Mininet with XTerm windows (__for regular TCP sawtooth__, with limited link capacity):
```
$ sudo mn --custom mn.py --topo congestion --link tc -x
```
To run Mininet __for attacks__ (with Mininet default link capacity, sufficiently large):
```
$ sudo mn --custom mn.py --topo standard --link tc -x
```

Run sender on host h1:
```
$ python reno.py --role sender --host h1 --verbose
```
Run receiver on host h2:
```
$ python reno.py --role receiver --host h2 --verbose
```
You should be able to see the changes of the sender's congestion control state and cwnd in its XTerm output. 

Besides `--role` and `--host`, `reno.py` also provides other flags to customize its behaviour:

* Use `--verbose` to log all sent and received packets in the terminal window. Regardless of this flag, the receiver's SEQ/ACK will be logged to "log.txt" or "log_attack.txt" if the receiver is an attacker.

* Use `--limit` to specify the amount of data the _sender_ would send (in kB). Both clients would tear down the connection when the limit is reached. So that data ping-pong would not go on forever.

* Use `--rtt` to specify the round-trip delay (in ms). For simplicity, our TCP implementation does not dynamically estimate the retranmission timeout (RTO). It is set to 4 times RTT statically and is default to 2s. Setting `--rtt` will set RTO accordingly, but RTO will not be shorter than 1s.

We also implemented several defense mechanisms with a 32-bit nonce. Each TCP segment will be sent with a randomly generated nonce. Each ACK has to reply with one nonce, and the ACK is only valid (for the data sender) if its nonce matches one of the sent segments' nonce. _One nonce is only valid for one ACK._

Run sender/receiver with defense mechanisms (nonce layer) on:
```
$ python reno_enhanced.py --role sender --host h1 --verbose
$ python reno_enhanced.py --role receiver --host h2 --verbose
```
You should see no difference in the behavior for regular TCP communication, but if you try to run any attack against `reno_enhanced.py`, you will get "invalid ACK" all the time and the sender does not blow up its congestion window.


## Attacker Commands
Instead of running `reno.py` in receiver mode, run `attacker.py` to mount receiver attacks.

To run ACK Division attacker on host h2:
```
$ python attacker.py --attack div --num 50 --host h2 --verbose
```

To run DupACK Spoofing attacker on host h2:
```
$ python attacker.py --attack dup --num 50 --host h2 --verbose 
```

To run Optimistic ACKing attacker on host h2:
```
$ python attacker.py --attack opt --num 50 --interval 10 --host h2 --verbose
```

The parameter `--num` specifies how many divided, spoofed, or optimistic ACKs to send on the first received data segment. The parameter `--interval` specifies the time between two optimistic ACKs in the Optimistic ACKing attack. 


## Plot the Sequence / Acknowledge Numbers
After running a regular TCP ping-pong or one of the attacks (div, dup, opt), you can generate the comparison plot for the attack you just ran by executing:
```
$ python plot.py --attack THE_ATTACK_NAME_YOU_JUST_RAN (div, dup, opt)
```

The parameter `--save` saves the plot instead of displaying it, and the parameter `--output` specifies the output directory.
