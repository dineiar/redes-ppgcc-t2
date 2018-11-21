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
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=5, hard_timeout=5, flags=ofproto.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=5, hard_timeout=5, flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)

    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        out_port = ofp.OFPP_FLOOD

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        # self.logger.info("packet in %s %s", dp.id, msg.in_port)
        self.logger.info("packet in %s %s %s %s", dp.id, src, dst, in_port)

        icmppkt = pkt.get_protocols(icmp.icmp)
        if icmppkt != []:
            if (icmppkt[0].type == 3 and icmppkt[0].code == 3 and isinstance(icmppkt[0].data, icmp.dest_unreach)):
                print "> Very likely a BlackNurse packet. Add a flow for the next 5 seconds: ", icmppkt[0]

                actions = [ofp_parser.OFPActionOutput(out_port)]
                match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, icmpv4_type=3, icmpv4_code=3)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out

                print(match)

                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    self.add_flow(dp, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(dp, 1, match, actions)
        
        # print("========================\n")
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        dp.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        match = msg.match

        print("Flow REMOVED")

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT or msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            print "Flow timeout"
        
        print 'OFP v3?', ofp.OFP_VERSION==ofproto_v1_3.OFP_VERSION, ofp.OFP_VERSION
        print str(match)
        if 'icmpv4_type' in match:
            print 'icmpv4_type: ', match['icmpv4_type']
            # help(match)

            if match['icmpv4_type'] == 3 and match['icmpv4_code'] == 3:
                packets = msg.packet_count
                seconds = msg.duration_sec
                if packets/seconds > 1000:
                    print "blocking "+str(match)+" for blacknurse"
                    # add_flow(bloqueia esse mac)
        else:
            print 'No ICMPv4_type field'
