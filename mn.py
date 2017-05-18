from mininet.topo import Topo

class MyTopo(Topo):
  def __init__(self):
    Topo.__init__(self)
    h1 = self.addHost('h1', ip='10.0.0.1')
    h2 = self.addHost('h2', ip='10.0.0.2')
    s1 = self.addSwitch('s1')
    self.addLink(h1, s1, bw=5, delay=50)
    self.addLink(h2, s1, bw=0.054, delay=50, max_queue_size=10)

topos = {'mytopo': (lambda: MyTopo())}

