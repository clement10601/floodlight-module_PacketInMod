package net.floodlightcontroller.headerextract;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.loadbalancer.LBMember;
import net.floodlightcontroller.loadbalancer.LBPool;
import net.floodlightcontroller.loadbalancer.LBVip;
import net.floodlightcontroller.loadbalancer.LoadBalancer;
import net.floodlightcontroller.loadbalancer.LoadBalancer.IPClient;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.util.OFMessageDamper;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.OFMessageDamper;

public class HeaderExtract implements IFloodlightModule, IOFMessageListener {

	public final int DEFAULT_CACHE_SIZE = 10;
	
	protected static Logger log = LoggerFactory.getLogger(LoadBalancer.class);
	protected IFloodlightProviderService floodlightProvider;
	protected IDeviceService deviceManager;
	protected IRestApiService restApi;
	protected ITopologyService topology;
	protected IRoutingService routingEngine;
	
	
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected HashMap<Integer, String> vipIpToId;
	protected HashMap<String, LBVip> vips;
	protected HashMap<String, LBPool> pools;
	protected ICounterStoreService counterStore;
    protected OFMessageDamper messageDamper;
	
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // ms. 
    protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms 
    protected String servIP = "10.0.0.1";

	
	public class IPClient {
        int ipAddress;
        byte nw_proto;
        
        short srcPort; // tcp/udp src port. icmp type (OFMatch convention)  
        short targetPort; // tcp/udp dst port, icmp code (OFMatch convention)
        
        public IPClient() {
            ipAddress = 0;
            nw_proto = 0;
            srcPort = -1;
            targetPort = -1;
        }
    }
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		//return null;
		return "HeaderExtract";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		
		return name.equals("forwarding");
	}

	@Override
	public Command receive(
		IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		//return null;
		OFPacketIn pi = (OFPacketIn) msg;
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		
		switch (msg.getType()) 
		{
			case PACKET_IN:
				return processPacketIn(sw,pi, match, cntx);
			default:
				break;
		}
		return Command.CONTINUE;
	}
	public Command processPacketIn
	(IOFSwitch sw, OFPacketIn pi, OFMatch match, FloodlightContext cntx) 
	{
	
		Ethernet eth = 
				IFloodlightProviderService.bcStore.get(
						cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		IPacket pkt = eth.getPayload();
		SwitchPort[] dsp = null;
		IOFSwitch dsw = null;
		short dstswport = 0;
		
		if (eth.isBroadcast() || eth.isMulticast()) 
		{
			return Command.CONTINUE;
        }
		else 
        {
			if (pkt instanceof IPv4) 
			{			
				int dstport =(int)(match.getTransportDestination());
				IPv4 v4pkt = ((IPv4) pkt);
				
                if (v4pkt.getPayload() instanceof UDP && dstport == 5134) 
                {
                	
                    IDevice dstDevice = null;
                    boolean found=false;
                    
                	v4pkt.setDestinationAddress(servIP);
                	v4pkt.resetChecksum();
                	eth.setPayload(v4pkt);
                	
                    while(found==false){
                    	Collection<? extends IDevice> devs =  deviceManager.getAllDevices();
                    	IDevice testdev = deviceManager.findDevice(
                    			0, null, IPv4.toIPv4Address(servIP), null, null);
                	for (IDevice dev : devs) {
                        for (int j = 0; j < dev.getIPv4Addresses().length; j++) {
                        	
                        	if(dev.getIPv4Addresses()[j]==IPv4.toIPv4Address(servIP))
                        	{
                        		dstDevice = dev;
                            	eth.setDestinationMACAddress(dstDevice.getMACAddressString());
                            	
                            	dsp = dstDevice.getAttachmentPoints();
                            	dsw = floodlightProvider.getSwitch(dsp[0].getSwitchDPID());
                            	dstswport = (short) dsp[0].getPort();
                            	System.out.println("outPort: "+dsp[0].getPort());
                            	
                            	eth.resetChecksum();
                            	
                            	pushPacket
                            	(
                            			eth, 
                            			dsw, 
                            			OFPacketOut.BUFFER_ID_NONE, 
                            			pi.getInPort(),
                            			dstswport, 
                            			cntx, 
                            			true
                            	);
                            	
                            	found = true;
                        	}
                        }
                    	} 
                    }
            		return Command.STOP;
                }
            }
        	
        }
		return Command.CONTINUE;
	}
	
    public void pushPacket(
    		IPacket packet, 
            IOFSwitch sw,
            int bufferId,
            short inPort,
            short outPort, 
            FloodlightContext cntx,
            boolean flush) 
    {
    	IPv4 v4pkt = (IPv4) packet.getPayload();
    	
    	
    	if (log.isTraceEnabled()) 
    	{
    		log.trace("PacketOut srcSwitch={} inPort={} outPort={}", 
    		new Object[] {sw, inPort, outPort});
    	}

    	OFPacketOut po =
    			(OFPacketOut) floodlightProvider.getOFMessageFactory()
    		    .getMessage(OFType.PACKET_OUT);

    	// set actions
    	List<OFAction> actions = new ArrayList<OFAction>();
    	actions.add(new OFActionOutput(outPort, (short) 0xffff));

    	po.setActions(actions)
    	.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
    	short poLength =
    			(short) (po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);

    	// set buffer_id, in_port
    	po.setBufferId(bufferId);
    	po.setInPort(inPort);

    	// set data - only if buffer_id == -1
    	if (po.getBufferId() == OFPacketOut.BUFFER_ID_NONE) 
    	{
    		
    	byte[] packetData = packet.serialize();
    	poLength += packetData.length;
    	po.setPacketData(packetData);
    	}

    	po.setLength(poLength);
    	try {
    		
    		System.out.println("!!!!Push Packet!!!!");
        	System.out.println("outPort: "+ outPort);
        	System.out.println("srcIP: "+IPv4.fromIPv4Address(v4pkt.getSourceAddress()));
        	System.out.println("srcAddr: "+ ((Ethernet)packet).getSourceMAC().toString());
        	System.out.println("dstIP: "+IPv4.fromIPv4Address(v4pkt.getDestinationAddress()));
        	System.out.println("dstAddr: "+ ((Ethernet)packet).getDestinationMAC().toString());
        	System.out.println("vSwitch IP: "+sw.getInetAddress());
        	
        	messageDamper.write(sw, po, cntx, flush);
        } catch (IOException e) {
            log.error("Failure writing packet out", e);
        }

    }

	
	
	@Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // We don't export any services
        return null;
    }
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
        	new ArrayList<Class<? extends IFloodlightService>>();
    		l.add(IFloodlightProviderService.class);
    		l.add(IDeviceService.class);
            l.add(IRoutingService.class);
            l.add(ITopologyService.class);
            l.add(ICounterStoreService.class);
            l.add(IStaticFlowEntryPusherService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {

		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		deviceManager = context.getServiceImpl(IDeviceService.class);
		macAddresses = new ConcurrentSkipListSet<Long>();
		topology = context.getServiceImpl(ITopologyService.class);
		routingEngine =  context.getServiceImpl(IRoutingService.class);
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY, 
                EnumSet.of(OFType.FLOW_MOD),
                OFMESSAGE_DAMPER_TIMEOUT);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {

		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}

}
