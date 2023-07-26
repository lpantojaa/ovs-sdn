from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import inet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from webob import Response
import json
from threading import Timer

Base = declarative_base()

# Define the table
class MacAddress(Base):
    __tablename__ = 'mac_addresses'
    mac = Column(String, primary_key=True)

engine = create_engine('sqlite:////home/leandro/finalproject/whitelist.db')
Session = sessionmaker(bind=engine)
session = Session()

# Define the controller for our API
class FlowManagementController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FlowManagementController, self).__init__(req, link, data, **config)
        self.app = data['app']

    @route('flows', '/flows/allow_port_443', methods=['POST'])
    def allow_port_443(self, req, **kwargs):
        try:
            body = json.loads(req.body)
            print(body)
            dpid = body['dpid']
            mac = body['mac']
            self.app.allow_port_443_flow(dpid,mac)
            return Response(status=200)
        except Exception as e:
            return Response(status=400, body=str(e))

# Define the switch application
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet, 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        wsgi = kwargs['wsgi']
        wsgi.register(FlowManagementController, {'app': self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        # Store the datapath instance
        self.datapaths[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions, hard_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if hard_timeout is not None:
            mod = parser.OFPFlowMod(datapath=datapath, hard_timeout=hard_timeout, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def allow_port_443_flow(self, dpid, mac_address):
        try:
            dpid = int(dpid)
        except ValueError:
            print(f"Invalid datapath ID: {dpid}")
            return
        datapath = self.datapaths.get(dpid)

        if datapath is None:
            return
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_src=mac_address, eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, tcp_dst=443)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions, hard_timeout=60)
        # Set a timer to remove MAC from whitelist after hard_timeout
        timer = Timer(60, self.remove_mac_from_whitelist, args=[mac_address])
        timer.start()

    def remove_mac_from_whitelist(self, mac_address):
        mac = session.query(MacAddress).filter_by(mac=mac_address).first()
        if mac is not None:
            session.delete(mac)
            session.commit()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time
        self.mac_to_port[dpid][src] = in_port

        # Whitelist check
        src_not_in_whitelist = session.query(MacAddress).filter_by(mac=src).first() is None

        if src_not_in_whitelist:
            # New device connected, block access to port 443
            match = parser.OFPMatch(eth_src=src, eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, tcp_dst=443)
            actions = []
            self.add_flow(datapath, 10, match, actions)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
