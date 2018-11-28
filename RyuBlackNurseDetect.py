from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp

class BlackNurseAwareSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BlackNurseAwareSwitch, self).__init__(*args, **kwargs)
        self.timeout_check = 5 #seconds
        self.packets_per_sec_threshold = 10
        self.timeout_block = 60 #seconds
        # self.packetslastsec = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def get_src_dst(msg_data):
        pkt = packet.Packet(msg_data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        return eth.src,eth.dst


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        out_port = ofproto.OFPP_FLOOD

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        # self.logger.info("packet in %s %s", datapath.id, msg.in_port)
        # self.logger.info("packet in %s %s %s %s", datapath.id, src, dst, in_port)

        send_packet_out = True

        icmppkt = pkt.get_protocols(icmp.icmp)
        if icmppkt != []:
            if (icmppkt[0].type == 3 and icmppkt[0].code == 3 and isinstance(icmppkt[0].data, icmp.dest_unreach)):
                self.logger.info("Very likely a BlackNurse packet. Add a flow for the next 5 seconds.")

                actions = [parser.OFPActionOutput(out_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=0x800, ip_proto=1, icmpv4_type=3, icmpv4_code=3)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out

                print(match)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    mod = parser.OFPFlowMod(datapath=datapath, buffer_id=msg.buffer_id, priority=1, match=match,
                        instructions=inst, hard_timeout=self.timeout_check, flags=ofproto.OFPFF_SEND_FLOW_REM)
                    send_packet_out = False
                else:
                    mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, 
                        instructions=inst, hard_timeout=self.timeout_check, flags=ofproto.OFPFF_SEND_FLOW_REM)
                
                datapath.send_msg(mod)
        
        if send_packet_out:
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = msg.match

        src = match['eth_src']
        
        if ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            if msg.reason == ofproto.OFPRR_HARD_TIMEOUT: # or msg.reason == ofproto.OFPRR_IDLE_TIMEOUT:
                self.logger.info("Flow removed, OpenFlow v1.3, removed by timeout")
                # print str(match)
                if 'icmpv4_type' in match and 'icmpv4_code' in match:
                    if match['icmpv4_type'] == 3 and match['icmpv4_code'] == 3:
                        packets = msg.packet_count
                        seconds = msg.duration_sec
                        self.logger.info("Flow matched %d packets in %d seconds: %d packets per sec", packets, seconds, packets/seconds)
                        if packets/seconds > self.packets_per_sec_threshold:
                            self.logger.info(">> Blocking "+src+" for blacknurse for " + str(self.timeout_block) + " seconds <<")

                            # Tell switch to drop the packets
                            # https://stackoverflow.com/a/41068251/3136474
                            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
                            match = parser.OFPMatch(eth_src=src, eth_type=0x800, ip_proto=1, icmpv4_type=3, icmpv4_code=3)
                            mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=match,
                                instructions=inst, hard_timeout=self.timeout_block)
                            datapath.send_msg(mod)
                else:
                    self.logger.info("No ICMPv4_type or ICMPv4_code fields on flow's match: %s", str(match))
            else:
                self.logger.info("Flow removed, reason: %s", str(msg.reason))
        else:
            self.logger.info("Flow removed, OpenFlow version: %d", ofproto.OFP_VERSION)
