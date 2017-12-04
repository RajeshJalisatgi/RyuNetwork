# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import mac
from ryu.lib.packet import ether_types



class CustomSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CustomSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def _build_ether(self, ethertype, dst_mac, _src_mac):
        e = ethernet.ethernet(dst_mac, _src_mac, ethertype)
        return e

    def _build_arp(self, opcode, dst_ip, src_ip):
        if opcode == arp.ARP_REPLY:
            _eth_dst_mac = self.ip_to_mac[dst_ip]
            _arp_dst_mac = self.ip_to_mac[dst_ip]
            _arp_src_mac = self.ip_to_mac[src_ip]

        e = self._build_ether(ether.ETH_TYPE_ARP, _eth_dst_mac, _arp_src_mac)
        a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                    opcode=opcode, src_mac=self.ip_to_mac[src_ip], src_ip=src_ip,
                    dst_mac=_arp_dst_mac, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        return p

    def _arp_request(self):
        p = self._build_arp(arp.ARP_REQUEST, ip)
        return p.data

    def _arp_reply(self, dst_ip, src_ip):
        p = self._build_arp(arp.ARP_REPLY, dst_ip, src_ip)
        return p.data   

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        
        
       
        SERVER_MAC = mac.haddr_to_bin('00:00:00:00:00:42')
        HOST_MAC = mac.haddr_to_bin('00:00:00:00:00:41')
        SERVER_IP = int(netaddr.IPAddress('192.168.1.2'))
        HOST_IP = int(netaddr.IPAddress('192.168.1.1'))

        ip_to_mac= {SERVER_IP:SERVER_MAC, HOST_IP:HOST_MAC}
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            p_arp = self._find_protocol(pkt, "arp")
            p_ipv4 = self._find_protocol(pkt, "ipv4")
            if p_arp:
                src_ip = str(netaddr.IPAddress(p_arp.src_ip))
                dst_ip = str(netaddr.IPAddress(p_arp.dst_ip))
                if p_arp.opcode == arp.ARP_REQUEST :
                    LOG.debug("--- PacketIn: ARP_Request: %s->%s", src_ip, dst_ip)
                    if p_arp.dst_ip == SERVER_IP) or (p_arp.dst_ip == HOST_IP) :
                        LOG.debug("--- send Pkt: ARP_Reply")
                        data = self._arp_reply(p_arp.src_ip, p_arp.dst_ip)
                        self._send_msg(dp, data)
                elif p_arp.opcode == arp.ARP_REPLY:
                    LOG.debug("--- PacketIn: ARP_Reply: %s->%s", src_ip, dst_ip)
                    LOG.debug("--- send Pkt: Echo_Request")            
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        p_ipv4 = self._find_protocol(pkt, "ipv4")

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[3][SERVER_MAC] = 1
        self.mac_to_port[3][HOST_IP] = 2
        self.mac_to_port[2][SERVER_MAC] = 1
        self.mac_to_port[2][HOST_IP] = 2
        self.mac_to_port[1][SERVER_MAC] = 1
        self.mac_to_port[1][HOST_IP] = 2

        self.logger.info("packet in dpid=%s src=%s dst=%s in_port=%s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        #self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
