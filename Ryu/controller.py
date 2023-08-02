# Import necessary modules from ryu library for the creation of the SDN controller
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

# Import necessary modules for database management and HTTP request handling
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from webob import Response
import json
from threading import Timer

Base = declarative_base()

# Define the database table
class MacAddress(Base):
    __tablename__ = 'mac_addresses'
    mac = Column(String, primary_key=True)

# Create engine for SQLite database
engine = create_engine('sqlite:////home/leandro/finalproject/whitelist.db')
Session = sessionmaker(bind=engine)
session = Session()

# Define the controller for our API, to manage the flows
class FlowManagementController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FlowManagementController, self).__init__(req, link, data, **config)
        self.app = data['app']

    # Define a route to allow port 443 for a specific MAC address
    @route('flows', '/flows/allow_port_443', methods=['POST'])
    def allow_port_443(self, req, **kwargs):
        try:
            body = json.loads(req.body)
            print(body)
            dpid = body['dpid']
            mac = body['mac']
            # Call the function to add the flow that allows port 443 for the specified MAC address
            self.app.allow_port_443_flow(dpid, mac)
            return Response(status=200)
        except Exception as e:
            return Response(status=400, body=str(e))

# Define the SDN application for the switch
class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet, 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {} # Dictionary to keep track of MAC addresses and their corresponding ports
        self.datapaths = {} # Dictionary to keep track of datapaths (switches)

        wsgi = kwargs['wsgi']
        # Register the flow management controller
        wsgi.register(FlowManagementController, {'app': self})

    # Event handler for switch features (invoked at the start of the connection)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Add default flow to send all packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        # Store the datapath instance
        self.datapaths[datapath.id] = datapath

    # Function to add flows to the switch
    def add_flow(self, datapath, priority, match, actions, hard_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # If a hard_timeout is specified, add it to the flow
        if hard_timeout is not None:
            mod = parser.OFPFlowMod(datapath=datapath, hard_timeout=hard_timeout, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    # Function to add a flow allowing TCP traffic to port 443
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
        # Add the flow with a hard_timeout of 60 seconds
        self.add_flow(datapath, 100, match, actions, hard_timeout=60)
        # Set a timer to remove MAC from whitelist after hard_timeout
        timer = Timer(60, self.remove_mac_from_whitelist, args=[mac_address])
        timer.start()

    # Function to remove a MAC address from the whitelist
    def remove_mac_from_whitelist(self, mac_address):
        mac = session.query(MacAddress).filter_by(mac=mac_address).first()
        if mac is not None:
            session.delete(mac)
            session.commit()

    # Event handler for PacketIn events (invoked when the switch receives a packet it does not have a flow for)
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

        # learn a mac address to avoid FLOOD next time
        self.mac_to_port[src] = in_port

        # Whitelist check
        src_not_in_whitelist = session.query(MacAddress).filter_by(mac=src).first() is None

        # If the source MAC address is not in the whitelist, block access to port 443
        if src_not_in_whitelist:
            match = parser.OFPMatch(eth_src=src, eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, tcp_dst=443)
            actions = []
            self.add_flow(datapath, 10, match, actions)

        # If the destination MAC address is known, get the corresponding port, otherwise flood
        if dst in self.mac_to_port:
            out_port = self.mac_to_port[dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # Create a PacketOut message to send the packet
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)