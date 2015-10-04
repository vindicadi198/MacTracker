package net.floodlightcontroller.mactracker;

import java.io.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
//import org.openflow.protocol.OFTypeTest;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import net.floodlightcontroller.learningswitch.LearningSwitch;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.staticflowentry.StaticFlowEntryPusher;

import org.openflow.util.HexString;
import org.python.antlr.PythonParser.classdef_return;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MACTracker implements IFloodlightModule, IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;

	// protected Set macAddresses;
	class switch_struct {
		public Long dpID;
		public HashMap<Integer, Integer> port_to_slice;
		public HashMap<Integer, ArrayList<Integer>> slice_to_ports;
		public HashMap<Long, Integer> mac_to_port;

		switch_struct() {
			port_to_slice = new HashMap<Integer, Integer>();
			slice_to_ports = new HashMap<Integer, ArrayList<Integer>>();
			mac_to_port = new HashMap<Long, Integer>();
		}
	}

	int TRUNK = Integer.MAX_VALUE;
	HashMap<Long, switch_struct> dpid_to_switch;
	HashMap<Long, Integer> mac_to_slice;
	protected static Logger logger;

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		String name = "MACTracker";
		return name;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		if(msg.getType() != OFType.PACKET_IN)
			return Command.CONTINUE;
		OFPacketIn in = (OFPacketIn) msg;
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		Long sourceMACHash = Ethernet.toLong(eth.getSourceMACAddress());
		Long destMacAddr = Ethernet.toLong(eth.getDestinationMACAddress());
		logger.warn("Packet in from "+sw.getId());
		long dpid = sw.getId();
		for(long i = 1;i<=2;i++){
			switch_struct sw1=dpid_to_switch.get(i);
			if(sw1==null)
				logger.warn("Switch struct null"+i);
		}
		switch_struct in_sw = dpid_to_switch.get(dpid);
		int in_port = in.getInPort();
		logger.warn("In port is "+in.getInPort());
		
		if(in_sw.port_to_slice.get(in_port)==null){
			System.out.println(in_sw.port_to_slice.keySet());
			logger.warn("slice not found");
		}
		int slice = in_sw.port_to_slice.get(in_port);
		if(slice==TRUNK)
			slice = mac_to_slice.get(sourceMACHash);
		if (mac_to_slice.get(sourceMACHash) == null)
			mac_to_slice.put(sourceMACHash, slice);
		if (in_sw.mac_to_port.get(sourceMACHash) == null) {
			in_sw.mac_to_port.put(sourceMACHash, (int) in.getInPort());
		}
		if (in_sw.mac_to_port.get(destMacAddr) == null) {
			floodPacketWithinSlice(sw, msg, slice,cntx);
		} else {
			short outport = in_sw.mac_to_port.get(destMacAddr).shortValue();
			sendPacketWithRule(sw, msg, outport);
		}
		return Command.CONTINUE;
		// return null;
	}

	public void floodPacketWithinSlice(IOFSwitch sw, OFMessage msg, int slice,FloodlightContext cntx) {
		logger.info("Flooding on switch" + sw.getId());
		switch_struct sw_db = dpid_to_switch.get(sw.getId());
		OFPacketIn pi = (OFPacketIn) msg;
		if (pi == null) {
			return;
		}
		// The assumption here is (sw) is the switch that generated the
		// packet-in. If the input port is the same as output port, then
		// the packet-out should be ignored.
		/*
		 * if (pi.getInPort() == outport) { if (log.isDebugEnabled()) {
		 * log.debug("Attempting to do packet-out to the same " +
		 * "interface as packet-in. Dropping packet. " +
		 * " SrcSwitch={}, match = {}, pi={}", new Object[]{sw, match, pi});
		 * return; } }
		 */
		OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.PACKET_OUT);

		// set actions
		List<OFAction> actions = new ArrayList<OFAction>();
		ArrayList<Integer> ports = sw_db.slice_to_ports.get(slice);
		// actions.add(new OFActionOutput(OFPort.OFPP_FLOOD.getValue(),
          //       (short)0xFFFF));
		int actionLength=0;
		for (Integer outport : ports) {
			actions.add(new OFActionOutput(outport.shortValue()).setMaxLength((short)0xffff));
		}
		ports = sw_db.slice_to_ports.get(TRUNK);
		for (Integer outport : ports) {
			actions.add(new OFActionOutput(outport.shortValue()).setMaxLength((short)0xffff));
		}
		actionLength=actions.size();
		
		po.setActions(actions).setActionsLength(
				(short) (OFActionOutput.MINIMUM_LENGTH*actionLength));
		//po.setLengthU((short)(actionLength+OFPacketOut.MINIMUM_LENGTH));
		//po.setActionsLength((short)actionLength);
		short poLength = (short) (po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);

		// If the switch doens't support buffering set the buffer id to be none
		// otherwise it'll be the the buffer id of the PacketIn
		if (sw.getBuffers() == 0) {
			// We set the PI buffer id here so we don't have to check again
			// below
			pi.setBufferId(OFPacketOut.BUFFER_ID_NONE);
			po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		} else {
			po.setBufferId(pi.getBufferId());
		}

		po.setInPort(pi.getInPort());

		// If the buffer id is none or the switch doesn's support buffering
		// we send the data with the packet out
		if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = pi.getPacketData();
			poLength += packetData.length;
			po.setPacketData(packetData);
		}

		po.setLength(poLength);

		try {
			sw.write(po, null);
		} catch (IOException e) {
			logger.error("Failure writing packet out", e);
		}
	}

	private void writeFlowMod(IOFSwitch sw, short command, int bufferId,
			OFMatch match, short outPort) {
		// from openflow 1.0 spec - need to set these on a struct ofp_flow_mod:
		// struct ofp_flow_mod {
		// struct ofp_header header;
		// struct ofp_match match; /* Fields to match */
		// uint64_t cookie; /* Opaque controller-issued identifier. */
		//
		// /* Flow actions. */
		// uint16_t command; /* One of OFPFC_*. */
		// uint16_t idle_timeout; /* Idle time before discarding (seconds). */
		// uint16_t hard_timeout; /* Max time before discarding (seconds). */
		// uint16_t priority; /* Priority level of flow entry. */
		// uint32_t buffer_id; /* Buffered packet to apply to (or -1).
		// Not meaningful for OFPFC_DELETE*. */
		// uint16_t out_port; /* For OFPFC_DELETE* commands, require
		// matching entries to include this as an
		// output port. A value of OFPP_NONE
		// indicates no restriction. */
		// uint16_t flags; /* One of OFPFF_*. */
		// struct ofp_action_header actions[0]; /* The action length is inferred
		// from the length field in the
		// header. */
		// };

		OFFlowMod flowMod = (OFFlowMod) floodlightProvider
				.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		flowMod.setMatch(match);
		flowMod.setCookie(LearningSwitch.LEARNING_SWITCH_COOKIE);
		flowMod.setCommand(command);
		flowMod.setIdleTimeout((short) 5);
		flowMod.setHardTimeout((short) 0);
		flowMod.setPriority((short) 100);
		flowMod.setBufferId(bufferId);
		flowMod.setOutPort((command == OFFlowMod.OFPFC_DELETE) ? outPort
				: OFPort.OFPP_NONE.getValue());
		flowMod.setFlags((command == OFFlowMod.OFPFC_DELETE) ? 0
				: (short) (1 << 0)); // OFPFF_SEND_FLOW_REM
		
		// set the ofp_action_header/out actions:
		// from the openflow 1.0 spec: need to set these on a struct
		// ofp_action_output:
		// uint16_t type; /* OFPAT_OUTPUT. */
		// uint16_t len; /* Length is 8. */
		// uint16_t port; /* Output port. */
		// uint16_t max_len; /* Max length to send to controller. */
		// type/len are set because it is OFActionOutput,
		// and port, max_len are arguments to this constructor
		flowMod.setActions(Arrays.asList((OFAction) new OFActionOutput(outPort,
				(short) 0xffff)));
		flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

		if (logger.isTraceEnabled()) {
			logger.trace("{} {} flow mod {}",
					new Object[] {
							sw,
							(command == OFFlowMod.OFPFC_DELETE) ? "deleting"
									: "adding", flowMod });
		}

		// counterStore.updatePktOutFMCounterStoreLocal(sw, flowMod);

		// and write it out
		try {
			sw.write(flowMod, null);
		} catch (IOException e) {
			logger.error("Failed to write {} to switch {}", new Object[] {
					flowMod, sw }, e);
		}
	}

	private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi,
			short outport) {
		if (pi == null) {
			return;
		}
		OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.PACKET_OUT);

		// set actions
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(new OFActionOutput(outport, (short) 0xffff));

		po.setActions(actions).setActionsLength(
				(short) OFActionOutput.MINIMUM_LENGTH);
		short poLength = (short) (po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);

		// If the switch doens't support buffering set the buffer id to be none
		// otherwise it'll be the the buffer id of the PacketIn
		if (sw.getBuffers() == 0) {
			// We set the PI buffer id here so we don't have to check again
			// below
			pi.setBufferId(OFPacketOut.BUFFER_ID_NONE);
			po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		} else {
			po.setBufferId(pi.getBufferId());
		}

		po.setInPort(pi.getInPort());

		// If the buffer id is none or the switch doesn's support buffering
		// we send the data with the packet out
		if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = pi.getPacketData();
			poLength += packetData.length;
			po.setPacketData(packetData);
		}

		po.setLength(poLength);

		try {
			sw.write(po, null);
		} catch (IOException e) {
			logger.error("Failure writing packet out", e);
		}
	}

	public void sendPacketWithRule(IOFSwitch sw,OFMessage msg,short outport){
		OFMatch match = new OFMatch();
		OFPacketIn pi = (OFPacketIn)msg;
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac = Ethernet.toLong(match.getDataLayerDestination());
        
        // Add flow table entry matching source MAC, dest MAC, VLAN and input port
        // that sends to the port we previously learned for the dest MAC/VLAN.  Also
        // add a flow table entry with source and destination MACs reversed, and
        // input and output ports reversed.  When either entry expires due to idle
        // timeout, remove the other one.  This ensures that if a device moves to
        // a different port, a constant stream of packets headed to the device at
        // its former location does not keep the stale entry alive forever.
        // FIXME: current HP switches ignore DL_SRC and DL_DST fields, so we have to match on
        // NW_SRC and NW_DST as well
        match.setWildcards(((Integer)sw.getAttribute(IOFSwitch.PROP_FASTWILDCARDS)).intValue()
        		& ~OFMatch.OFPFW_IN_PORT
        		& ~OFMatch.OFPFW_DL_VLAN & ~OFMatch.OFPFW_DL_SRC & ~OFMatch.OFPFW_DL_DST
        		& ~OFMatch.OFPFW_NW_SRC_MASK & ~OFMatch.OFPFW_NW_DST_MASK);
        // We write FlowMods with Buffer ID none then explicitly PacketOut the buffered packet
        this.pushPacket(sw, match, pi, outport);
        this.writeFlowMod(sw, OFFlowMod.OFPFC_ADD, OFPacketOut.BUFFER_ID_NONE, match, outport);
        /*if (LEARNING_SWITCH_REVERSE_FLOW) {
        	this.writeFlowMod(sw, OFFlowMod.OFPFC_ADD, -1, match.clone()
        			.setDataLayerSource(match.getDataLayerDestination())
        			.setDataLayerDestination(match.getDataLayerSource())
        			.setNetworkSource(match.getNetworkDestination())
        			.setNetworkDestination(match.getNetworkSource())
        			.setTransportSource(match.getTransportDestination())
        			.setTransportDestination(match.getTransportSource())
        			.setInputPort(outPort),
        			match.getInputPort());
            */
		
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		//l.add(StaticFlowEntryPusher.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(MACTracker.class);
		dpid_to_switch = new HashMap<Long, switch_struct>();
		mac_to_slice = new HashMap<Long, Integer>();
		File topo = new File(
				"/Users/adityakamath/Documents/iith/sem6/tin/topo.txt");
		try {
			BufferedReader br = new BufferedReader(new FileReader(topo));
			while (br.ready()) {
				String line = br.readLine();
				String[] parsed = line.split(",");
				Long dpid = Long.parseLong(parsed[0]);
				dpid_to_switch.put(dpid, new switch_struct());
				for (int i = 1; i < parsed.length; i++) {
					String[] port_slice = parsed[i].split(":");
					int port = Integer.parseInt(port_slice[0]);
					int slice = Integer.parseInt(port_slice[1]);
					switch_struct sw = dpid_to_switch.get(dpid);
					sw.port_to_slice.put(port, slice);
					if (sw.slice_to_ports.get(slice) == null) {
						ArrayList<Integer> ports = new ArrayList<Integer>();
						ports.add(port);
						sw.slice_to_ports.put(slice, ports);
					} else {
						ArrayList<Integer> ports = sw.slice_to_ports.get(slice);
						ports.add(port);
					}
				}
			}
			br.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

}
