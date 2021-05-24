# XDP Firewall

## Goals

* A firewall that runs at the XDP level
* Dynamicly generated XDP program from rule-set
* Configurable rule source
    * IPTables, parse 'iptables-save' output so it is compatible with existing linux infra.
        Most likely only a subset of iptable features.
    * Flowspec (via GoBGP), so it is compatible with network filtering
    * Firewall rules as yaml (for config via tools like ansible)
    * gRPC API so tools can directly intergrate
    * CLI (which uses gRPC API) for admin management
    * [DDoS Dissector](https://github.com/ddos-clearing-house/ddos_dissector)
* Be compatible with other XDP programs (callable via tail call or attach directly to netdev)
* Statistics per rule

## TODO

* IPv4 partial field matching (we can already match whole fields 8, 16, and 32 bits. But not yet single bits or nibbels)
* IPset matching (matching a IP address(v4 or v6) agains a list of ranges/single ips) implemented using a hash map or LPM map.
* Default L2 protocol exceptions(Allowing ARP and NDP so local area networking keeps working)
* Rule statistics (amounts rule hits)
* Block actin (use TX action to send back an ICMP "port unreachable message")
* Jump action (jumping to skip rules)
* Rate limit action
* ? Flow tracking (some day maybe)

### Protocols / network layers

Since we can only filter packets which we understand we must add parsing and matching for all protocols and network layers we want to support.
I have listend them in order of priority.

* Ethernet (We do not yet have filters)
* IPv6 (Not yet very widely used, but having a second L3 layer protocol is good for testing)
* TCP
* UDP
* ICMPv4/ICMPv6
* DNS
* NTP
* QinQ/Double tagging (having more than 1 VLAN header)
* VXLAN
* IP-in-IP
* GRE

## Architecture

* The firewall config consists of a few parts
    * Generic settings (File locations, API addresses, ect.)
    * Attached network devices (the firewall can be attached to multiple network devices but a network device can only have one firewall)
    * List of firewall rules
    * Default action (if no rules match)
* A rule consists of:
    * A name (optional)
    * A match (required) (when does the rule match?)
    * A action (what to do if the rule matches)
* Rules are executed in order unless a action interupts the flow
* The firewall starts evaluating each packet from the first rule
* A rule can jump to another rule (target by name) but only jumping forwards, never backwards (loop prevention)
* Some matches implicity add more matches, a 'TCP source port' match implicity can only be valid if the IP Protocol is TCP.
