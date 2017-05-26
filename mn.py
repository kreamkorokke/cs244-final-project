from mininet.topo import Topo

class CongestionTopo(Topo):
  def __init__(self):
    Topo.__init__(self)
    h1 = self.addHost('h1', ip='10.0.0.1')
    h2 = self.addHost('h2', ip='10.0.0.2')
    s1 = self.addSwitch('s1')
    self.addLink(h1, s1, bw=5, delay='50ms')
    self.addLink(h2, s1, bw=0.054, delay='50ms', max_queue_size=10)

class StandardTopo(Topo):
  def __init__(self):
    Topo.__init__(self)
    h1 = self.addHost('h1', ip='10.0.0.1')
    h2 = self.addHost('h2', ip='10.0.0.2')
    s1 = self.addSwitch('s1')
    self.addLink(h1, s1, delay='250ms')
    self.addLink(h2, s1, delay='250ms')

topos = { 'standard' : (lambda: StandardTopo()),
          'congestion': (lambda: CongestionTopo()) 
        }

