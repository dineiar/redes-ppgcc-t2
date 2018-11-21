from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp

class BlackNurseAwareSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BlackNurseAwareSwitch, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # self.logger.info("packet in %s %s", dp.id, msg.in_port)
        self.logger.info("packet in %s %s %s %s", dp.id, eth.src, eth.dst, msg.in_port)

        icmppkt = pkt.get_protocols(icmp.icmp)
        if icmppkt != [] :
            if (icmppkt[0].type == 3 and icmppkt[0].code == 3 and isinstance(icmppkt[0].data, icmp.dest_unreach)):
                print "> Very likely a BlackNurse packet. Check if it's flooding: ", icmppkt[0]

        print("========================\n")

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        dp.send_msg(out)
