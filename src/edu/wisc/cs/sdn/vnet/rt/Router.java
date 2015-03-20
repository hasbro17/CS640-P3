package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.packet.*;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Code for ipv4 ethertype */
	private final short IPV4ETHERTYPE = 0X0800;

	
	/** HashMap of IPs(key) resolved and their ARPRequester threads(value) packets waiting **/
	private ConcurrentHashMap<Integer, ARPRequester> activeThreads= new ConcurrentHashMap<Integer, ARPRequester>();
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	


	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}
	
	
	public ConcurrentHashMap<Integer, ARPRequester> getActiveThreads(){
		return activeThreads;
	}

	
	/**
	 * Generates ARP reply packet.
	 * @param etherPacket with the arp request payload for which this arp reply is generated
	 * @param inIface the interface of the incoming packet
	 * @return Ethernet packet with ARP payload for reply
	 */
	public Ethernet genArpReply(Ethernet etherPacket, Iface inIface)
	{
		ARP arpPacket = (ARP)etherPacket.getPayload();
		
		//Construct the ARP Reply
		Ethernet ether = new Ethernet();
		ARP arpReplyPacket = new ARP();
		
		//Set the fields for the Ethernet packet
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
		
		// Set the fields for the ARP Header
		arpReplyPacket.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpReplyPacket.setProtocolType(ARP.PROTO_TYPE_IP);
		
		/**********************Check the parameter************************************/
		arpReplyPacket.setHardwareAddressLength((byte)(Ethernet.DATALAYER_ADDRESS_LENGTH & 0xff));
		arpReplyPacket.setProtocolAddressLength((byte)4);
		
		arpReplyPacket.setOpCode(ARP.OP_REPLY);
		arpReplyPacket.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arpReplyPacket.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(inIface.getIpAddress()));
		arpReplyPacket.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
		arpReplyPacket.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
		
		// Set the ARP Packet as the Ethernet packet payload 
		ether.setPayload(arpReplyPacket);
		
		return ether;
	}

	
	/**
	 * Generates ARP request packet.
	 * @param etherPacket for which this arp request is generated
	 * @param outIface the interface of to send this request out on
	 * @return Ethernet packet with ARP payload for request
	 */
	public Ethernet genArpRequest(Ethernet etherPacket, Iface outIface)
	{
		IPv4 ipv4Packet = (IPv4)etherPacket.getPayload();
		
		byte [] broadcast= { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
		byte [] targHWAdd={0,0,0,0,0,0};
		
		//Construct the ARP Reply
		Ethernet ether = new Ethernet();
		ARP arpRequestPacket = new ARP();
		
		//Set the fields for the Ethernet packet
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(broadcast);
		
		// Set the fields for the ARP Header
		arpRequestPacket.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpRequestPacket.setProtocolType(ARP.PROTO_TYPE_IP);
		
		/**********************Check the parameter************************************/
		arpRequestPacket.setHardwareAddressLength((byte)(Ethernet.DATALAYER_ADDRESS_LENGTH & 0xff));
		arpRequestPacket.setProtocolAddressLength((byte)4);
		
		arpRequestPacket.setOpCode(ARP.OP_REQUEST);
		arpRequestPacket.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
		arpRequestPacket.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(outIface.getIpAddress()));
		arpRequestPacket.setTargetHardwareAddress(targHWAdd);
		
		//Target Protocol is IP of next Hop
		int nextHopIP;
		RouteEntry routeEntry = routeTable.lookup(ipv4Packet.getDestinationAddress());
		if(routeEntry.getGatewayAddress()==0)
			nextHopIP=ipv4Packet.getDestinationAddress();
		else
			nextHopIP=routeEntry.getGatewayAddress();

		arpRequestPacket.setTargetProtocolAddress(nextHopIP);
		
		// Set the ARP Packet as the Ethernet packet payload 
		ether.setPayload(arpRequestPacket);
		
		return ether;
	}
	
	

	/**
	 * Generates ICMP Time Exceeded packet. Can be tweaked for other ICMP message types
	 * @param etherPacket the incoming Ethernet packet for which this Time Exceeded is generated
	 * @param inIface the interface of the incoming packet
	 * @param srcMacAddress the original source MAC address of the incoming packet, previous hop
	 * @return null on error, ICMP ethernet packet on success
	 */
	public Ethernet genICMPTimeExceeded(Ethernet etherPacket, Iface inIface, byte[] srcMacAddress){

		IPv4 ipv4Packet = (IPv4)etherPacket.getPayload();

		//Generate ICMP packet with required headers
		Ethernet ether  = new Ethernet();
		IPv4 ip = new  IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		//Set ICMP header fields 
		icmp.setIcmpType((byte)11);
		icmp.setIcmpCode((byte)0);
		//Prepare data for ICMP payload
		byte[] ipBytes = ipv4Packet.serialize();
		int numIPBytes=ipv4Packet.getHeaderLength()*4 + 8;//IP header + 8 bytes following header
		System.out.println("\n\n IP header length: "+numIPBytes+"\n\n");

		byte[] icmpData = new byte[4 + numIPBytes];//4 bytes extra for padding
		for(int i=0; i<numIPBytes; i++)
			icmpData[i+4]=ipBytes[i];
		//Set ICMP data
		data.setData(icmpData);

		//Set IP header fields
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(ipv4Packet.getSourceAddress());

		//Set Mac header fields
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		
		//Destination MAC back to previous hop
		ether.setDestinationMACAddress(srcMacAddress);
		return ether;
	}


	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Router Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		//Original Source Mac address of previous hop
		byte[] originalSrcMAC=etherPacket.getSourceMACAddress();
		
		if(etherPacket.getEtherType() == Ethernet.TYPE_ARP){

		    System.out.println("\nHandling the arp packet");
			//handle the ARP Packet
			
			ARP arpPacket = (ARP)etherPacket.getPayload();
			int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
			
			int senderIp = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
			
			//check if the target IP is the inIface IP
			if(targetIp != inIface.getIpAddress()){
				//The ARP packet was not intended for us
				System.out.println("\nARP packet not for our inIface: "+inIface.toString());
				return ;
			}
			
			
			//ARP request received, need to send ARP reply
			if(arpPacket.getOpCode() == ARP.OP_REQUEST){
				System.out.println("\nGot Arp Request");	
				
				//Construct the ARP Reply
				Ethernet ether = genArpReply(etherPacket, inIface);
				// Send the reply through the interface through which we received the request
				sendPacket(ether, inIface);	
			}
			//ARP reply received
			//Need to update ARP cache and insert ARPreply enqueued packets on their way
			else{
				System.out.println("\nGot Arp Reply");

				//Consider only if ARP cache value for this IP is missing
				if(arpCache.lookup(senderIp)==null)
				{
					//Check if the requester is still active
					ARPRequester requester= activeThreads.get(senderIp);
					if(requester==null)
						return;
						
					//If requester is still waiting for replies from targetIp
					//Then the reply made it in time, forward the queued packets to their destination 
					if(!requester.isDone())
					{
						//Stop the ARP requester and give it the ARP reply
						requester.setReply(etherPacket, inIface);
						//update ARP cache for future packets for this IP address
						arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()), senderIp);
					}
					//else the Requester has timed out before reply came, it will send ICMP Dest Host unreachable for all queued packets
					//clear up requester for this IP
					activeThreads.remove(senderIp);
				}
			}
			return;
		}
		else if(etherPacket.getEtherType()!= this.IPV4ETHERTYPE){
			//Not IPv4 or ARP - drop the packet
			return;
		}

		
		IPv4 ipv4Packet = (IPv4)etherPacket.getPayload();

		//check the TTL and send ICMP Time Exceeded message
		if(ipv4Packet.getTtl() == 1){

			Ethernet ether=null;
			if( (ether=genICMPTimeExceeded(etherPacket, inIface, originalSrcMAC)) != null )
				sendPacket(ether, inIface);
			return;
		}

		//calculate the checksum
		short originalChecksum = ipv4Packet.getChecksum();

		//set checksum to 0
		ipv4Packet.setChecksum((short)0x0000);

		//serialize will compute the check sum again
		byte[] ipv4Bytes = ipv4Packet.serialize();

		//compare the original checksum with 10th and 11byte
		byte b1,b2;

		b1 = (byte)((originalChecksum >> 8) & 0xff);
		b2 = (byte)(originalChecksum & 0xff);

		if(!(b1 == ipv4Bytes[10] && b2 == ipv4Bytes[11])){
			//check sum mismatch
			return;
		}

		//Check if the packet's destination IP was for one of the router's interfaces
		Iterator<Iface> ifaceIt = interfaces.values().iterator();
		Iface tIface = null;
		while(ifaceIt.hasNext())
		{
			tIface = ifaceIt.next();
			if(tIface.getIpAddress() == ipv4Packet.getDestinationAddress()){

				Ethernet ether=genICMPTimeExceeded(etherPacket, inIface, originalSrcMAC);
				ICMP icmp=(ICMP) ether.getPayload().getPayload();
				icmp.setIcmpType((byte)3);	

				//ICMP Destination Port Unreachable
				if(ipv4Packet.getProtocol()==IPv4.PROTOCOL_TCP || ipv4Packet.getProtocol()==IPv4.PROTOCOL_UDP)
				{
					icmp.setIcmpCode((byte)3);
					sendPacket(ether, inIface);
				}
				//Echo Reply
				else if(ipv4Packet.getProtocol()==IPv4.PROTOCOL_ICMP)
				{
					ICMP icmpEchoReq=(ICMP) ipv4Packet.getPayload();	
					if(icmpEchoReq.getIcmpType()==8)
					{
						IPv4 ip = (IPv4) ether.getPayload();
						ip.setSourceAddress(ipv4Packet.getDestinationAddress());
						icmp.setIcmpType((byte)0);
						icmp.setIcmpCode((byte)0);
						icmp.setPayload(icmpEchoReq.getPayload());
						sendPacket(ether, inIface);
					}
				}
				return;
			}
		}

		//Look up route entry for forwarding packet
		RouteEntry routeEntry = routeTable.lookup(ipv4Packet.getDestinationAddress());

		//ICMP Dest Net unreachable
		if(routeEntry == null)
		{
			System.out.println("\nThe look up has failed");
			Ethernet ether=null;
			if( (ether=genICMPTimeExceeded(etherPacket, inIface, originalSrcMAC)) != null )
			{
				ICMP icmp=(ICMP) ether.getPayload().getPayload();
				icmp.setIcmpType((byte)3);
				icmp.setIcmpCode((byte)0);
				sendPacket(ether, inIface);
			}
			return;
		}

		System.out.println("\nDestination address = "+IPv4.fromIPv4Address(routeEntry.getDestinationAddress()));
		System.out.println("\nMask Address = "+IPv4.fromIPv4Address(routeEntry.getMaskAddress()));
		System.out.println("\nLooking to forward the packet");

		
		//form the corresponding IP packet

		//change the ttl and checksum
		ipv4Packet.setTtl((byte)(ipv4Packet.getTtl()-1));

		//calculate the new checksum
		ipv4Packet.setChecksum((short)(0x0000));
		ipv4Bytes = ipv4Packet.serialize();

		short s1 = (short)((ipv4Bytes[10] << 8) & 0xff00);
		short s2 = (short)(ipv4Bytes[11] & 0x00ff);

		ipv4Packet.setChecksum((short)(s1+s2));

		etherPacket.setPayload(ipv4Packet);
		
		//Set Source MAC Adress
		etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());
		

		//Find the corresponding destination MAC (next hop) for this IP address by an ARP lookup
		ArpEntry arpEntry = null;
		
		//Next hop IP address
		int nextHopIP;
		if(routeEntry.getGatewayAddress() == 0)
		{
			arpEntry = arpCache.lookup(ipv4Packet.getDestinationAddress());
			nextHopIP=ipv4Packet.getDestinationAddress();
		}
		else
		{
			arpEntry = arpCache.lookup(routeEntry.getGatewayAddress());
			nextHopIP=routeEntry.getGatewayAddress();
		}

		//Now generate ARP request for the IP address and queue any packets for any IP address being currently resolved
		if(arpEntry==null)
		{
			//check if requester exists and has not timed out(is not done)
			if(activeThreads.containsKey(nextHopIP) 
					&& !activeThreads.get(nextHopIP).isDone())
			{
				//add to requestor's queue of waiting packets
				activeThreads.get(nextHopIP).add(etherPacket, inIface, originalSrcMAC);

			}
			//if not then spawn a new thread to generate ARP requests for this IP address
			else
			{
				//Generate the ARP request packet for the new requester thread
				Ethernet etherARPReq = genArpRequest(etherPacket, routeEntry.getInterface());//inIface);
				
				//New ARP requester object
				ARPRequester r = new ARPRequester(etherARPReq, routeEntry.getInterface(), this);
				//Add packet, inIface and srcMAC to waiting queues
				r.add(etherPacket, inIface, originalSrcMAC);
				//Put new requester object in global map of active requesters for IP addresses
				//If an older object existed, it has timed out and is replaced by the new one
				activeThreads.put(nextHopIP, r);
				
				//Start a thread for ARP request generation and move on.
				Thread t= new Thread(r);
				t.start();
			}
			return;
		}

		MACAddress nextHopMAC = arpEntry.getMac();

		if( nextHopMAC == null){
			return;
		}
		else{
			
			etherPacket.setDestinationMACAddress(nextHopMAC.toBytes());

			sendPacket(etherPacket, routeEntry.getInterface());
		}
		/********************************************************************/
	}


	
}

