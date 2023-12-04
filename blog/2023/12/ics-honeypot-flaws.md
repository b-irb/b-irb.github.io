- 2023-12-03
- Flaws with ICS Honeypots

Industrial Control Systems (ICS) security is extremely important because ICS
devices are ubiquitous throughout critical infrastructure and services.
To emphasise this, unlike core IXPs or DFZ routers which are ancillary, ICS
devices are _directly_ involved in critical processes:
- water purification
- petrochemical processing
- agriculture
- electric grid management
- etc.

If ICS devices are compromised then critical services are immediately
disrupted.

## What do ICS devices _actually do_?

ICS devices provide a range of control and observability to human operators.
A common ICS device are Programmable Logic Controllers (PLCs) which are
essentially embedded computers running a proprietary RTOS hooked up to hardware
peripherals (e.g. sensors, actuators, valves, etc.). PLCs will often provide
remote services for an operator to observe and _modify_ the state of the PLC
(and its attached peripherals). The _modification of state_ allows an operator
to manipulate the _physical environment_.

PLCs can be grouped together under a Sypervisory Control and Data Acquisition
(SCADA) system to control and observe fleets of PLCs and other remote ICS
devices. With this, a human operator can control a complex process involving a
variety of devices (e.g. an entire production chain).

### Real-World Example

The Siemens S7-1200 PLC is a popular (although now dated) choice for operators
because it boasts a huge range of remote protocols: TCP, ISO-on-TCP, Step7,
MODBUS, HTTP(S), SNMP, LLDP, NTP, ARP, etc. In addition, the S7-1200 CPUs can
connect to multiple peripherals (e.g. 1212C has 8 and 6 digital inputs and
outputs, respectively and 2 analog inputs).

An operator can write a Ladder-Logic program for the PLC then attach hardware
periphals to available connectors (S7-1200 can add modules with more
connectors, memory, DSPs, etc). Then the operator can remotely interface with
the PLC individually or setup a SCADA system to poll the device on its state.

## PLC Honeypots

Honeypots are popular in academia because they allow researchers to understand
how attackers probe for and interact with ICS devices. The honeypots generally
aim to emulate a subset of protocols then record all network ad protocol
interactions. Popular honeypots include:
- GasPot (succeeded by XPOT)
- Conpot (succeeded by S7commTrace)
- Honeyd
- HoneyPLC (succeeded by ICSpot)
- HoneyPhy (succeeded by ICSpot)
- MiniCPS
- CryPLH

Honeypots can be viewed as having three core capabilities which we can tag
honeypots as implementing (excluding honeypots with successors):

| Capability          | Honeypot(s)                   |
|---------------------|-------------------------------|
| Stateful Protocols  | S7commTrace, ICSpot, Honeyd   |
| Network Emulation   | MiniCPS                       |
| Physical Simulation | ICSpot, CryPLH, MiniCPS, XPOT |

### Stateful Protocols

Common protocols implemented by honeypots are HTTP(S), SNMP, S7, MODBUS, and
ENIP. Of these, honeypots will attempt to provide all original functionality
of the target device (e.g. all hidden webpages are accessible). However, a key
problem with implementing these protocols are that an interactive attacker will
expect the same _state transitions_ as well as the same _implementation
behaviour_.

### Network Emulation

Honeypots are reachable over a network. A high-level protocol can be correctly
implemented but the lower level protocols may rely on the honeypot host rather
than an accurate emulation (e.g. TCP segmentation when sending HTTP requests).
However, the more hops between the target and the user, the more unreliable
these characteristics become (i.e. a network hop might reconstruct packets).
Despite this, an attacker can heuristically determine details about the network
stack/environment of the peer.

### Physical Simulation

PLCs do not sit idle; PLCs are supposed to be _doing stuff_. If an attacker is
able to inspect a device with no running logic or no peripherals, the device
is either suspicious or useless from an attacker POV. An attacker will
struggle to verify details of the physical simulation without gleaning details
off of running logic or other channels. However, an attacker _can_ assume that
the simulation behaves realistically (i.e. constant increments in sensor
readings).

## Implementations are fundamentally flawed

All honeypot implementations make tradeoffs over the accuracy of their
emulation against the ease of configuration. This results in behaviour being
correct _but inaccurate_. As an example, a common approach to support the
proprietary S7 protocol is to use Snap7, a library implementing a subset of
S7. This is unacceptable because Snap7 does not attempt to implement the entire
protocol nor does it attempt to mimic a real device. An attacker can rely on
undocumented features or implementation details of the legitimate S7 stack
to detect differences. This issue extends to other ICS protocols where the
implementors choose 3rd-party dependencies which are not perfectly identical:
Modbus, ENIP, ISO-on-TCP, HTTP, etc.

Attempting to emulate the network layer is also exceedingly difficult because
the networking stack of PLCs are proprietary and run on custom hardware with
a custom RTOS. You _cannot_ use a different TCP stack then hope to reconstruct
packets to mimic a target device without a very tedious configuration process
and a prayer that you correctly implemented all quirks. This also extends to
side-channels like processing delays, impacts on other tasks, debugging
interfaces tracking processor metrics, etc.

## Deployments are fundamentally flawed

The first two lists are well explored in literature (with the low-level
characteristics being frequently hand-waved away by implementors). However,
the issues with deployment are less explored (aside from having a natural
host appearance). From reading a variety of papers, all honeypots were hosted
on commercial cloud providers or university networks which are trivial to
tag as suspicious by looking at the target ASN.

Instead, we should try put the honeypot on an ASN owned by a business ISP which
is used by _industrial sites_. In addition an attacker can look at the routing
path to see if deployers have installed a network proxy, router, or switch
which can be suspicous because a PLC should not have a huge network path if it
is on the public Internet.

However the _biggest_ flaws with _all_ honeypot research I have read was the
_duration of the study_. The majority of honeypots were deployed for under
180 days with none spanning over 2 years. Consequently, an attacker can ignore
all peers until they have been consistently online for over 8 months. An
additional issue was that operators would often deploy several instances of
the same honeypot which can be an indicator that the honeypots are either:
1. Part of the same OT network.
2. All honeypots run by the same group.

The first scenario can be ruled out using the other networking characteristics.
The final issue I see when looking at deployments are network neighbours. A
network neighbour is a device on a nearby address (e.g. X.X.X.1 and X.X.X.2).
On a large network, you might expect a _range_ of addresses to be advertised to
the wider internet. Using this assumption, an attacker can see if the
surrounding hosts are hosting unrelated services (e.g. PLC neighbouring with
someone's 90s-style Internet homepage).

### My 2¢

Honeypots are junk. A sophisticated attacker will detect anything less than
genuine which is relevant because anyone targeting ICS devices will be
sophisticated. Even worse, the attacker will be sophisticated _and patient_
because ICS attackers will be state actors or state sponsored actors whose
motivations (the motivations of the state) are political. Instead, more effort
should be focused on adding instrumentation to real devices then putting those
devices into real OT networks. Overall interactions are significantly less
likely but the interactions that do occur will be extremely revealing in how
an actual ICS attacker behaves.

To elaborate on this, ICS attackers are not like traditional IT attackers. The
attackers will have complex intentions (i.e. not aiming to ransomware for a
quick buck), be experienced with working on PLCs, and will have access to
real devices to testbed exploits and compare responses. I do not think trying
to deceive this cohort is productive because you cannot win.

