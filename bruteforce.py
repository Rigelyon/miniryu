from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
import time
import socket
import struct

class AntiBruteForceSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION, ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AntiBruteForceSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ssh_attempts = {}
        self.SSH_PORT = 22
        self.THRESHOLD = 5
        self.WINDOW = 30
        self.BLOCK_TIME = 60
        print("--- Anti-Brute-Force Shield Active (Fix IP Integer) ---")

    # Fungsi pembantu untuk mengubah string IP ke Integer (untuk OF 1.0)
    def ip_to_int(self, ip_str):
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)
        else:
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0,
                                    command=ofproto.OFPFC_ADD, priority=priority,
                                    actions=actions, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            in_port = msg.match['in_port']
        else:
            in_port = msg.in_port

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == 0x88cc: return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip_pkt and tcp_pkt:
            if tcp_pkt.dst_port == self.SSH_PORT and (tcp_pkt.bits & 0x02):
                src_ip = ip_pkt.src
                curr = time.time()
                self.ssh_attempts.setdefault(src_ip, [])
                self.ssh_attempts[src_ip] = [t for t in self.ssh_attempts[src_ip] if curr - t <= self.WINDOW]
                self.ssh_attempts[src_ip].append(curr)
                
                print("[SSH-Attempt] IP: {0} | Count: {1}/{2}".format(src_ip, len(self.ssh_attempts[src_ip]), self.THRESHOLD))

                if len(self.ssh_attempts[src_ip]) >= self.THRESHOLD:
                    print("!!! BLOCKED {0} !!!".format(src_ip))
                    
                    if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
                        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                    else:
                        # KONVERSI KE INTEGER UNTUK OPENFLOW 1.0
                        src_ip_int = self.ip_to_int(src_ip)
                        match = parser.OFPMatch(dl_type=0x0800, nw_src=src_ip_int)
                    
                    self.add_flow(datapath, 100, match, [], hard_timeout=self.BLOCK_TIME)
                    return

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            else:
                match = parser.OFPMatch(in_port=in_port, dl_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)