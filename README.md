Overview

This is an [OpenFlow 1.3][ofp13] compatible user-space software switch implementation. The code is based on the [Ericsson TrafficLab 1.1 softswitch implementation][ericssonsw11], with changes in the forwarding plane to support OpenFlow 1.3.

The following components are available in the release:
  - ofdatapath - the switch implementation
  - ofprotocol - secure channel for connecting the switch to the controller
  - oflib - a library for converting to/from 1.3 wire format
  - dpctl - a tool for configuring the switch from the console
  
Installation

Circumstance instruction:
This software should compile under Unix-like environments which runs in lxc environment contained by CE switch.

Main steps:
  - Install CE switch with firmware which included lxc environment.
  - Pre-configure CE switch.
  - Install openflow in lxc.
  - Enable datapath progress.
  - Enable protocol progress.
  - Configure flow-table.

Example usage

Start the datapath:

$ ofdatapath enable ptcp:<port> -d <dpid> -I <Ethernet port IP> -f <configuration file>

The above command will start the datapath progress, with a passive tcp connection on the given port ,a given datapath id and the configuration file. For a complete list of options, use the `-h` argument.

Start the secure channel:

$ ofprotocol tcp:<switch-host>:<switch-port> tcp:<ctrl-host>:<ctrl-port> 

This command will open TCP connections to both the switch and the controller, relaying OpenFlow protocol messages between the two. For a complete list of options, use the `-h` argument.

You can send requests to the switch using the `dpctl` utility:

$ dpctl tcp:<switch-host>:<switch-port> stats-flow table=0

To install a flow:

$ dpctl tcp:<switch-host>:<switch-port> flow-mod table=0,cmd=add in_port=1,eth_type=0x86dd,ext_hdr=hop+dest apply:output=2

The example above install a flow to match IPv6 packets with extension headers hop by hop and destination and coming from the port 1.

References

[1] OpenFlow: Enabling Innovation in College Networks.  Whitepaper.
    <http://openflowswitch.org/documents/openflow-wp-latest.pdf>

[2] OpenFlow Switch Specification.
    <http://openflowswitch.org/documents/openflow-spec-latest.pdf>


