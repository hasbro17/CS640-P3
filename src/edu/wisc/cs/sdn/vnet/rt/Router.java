package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Iterator;

import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
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


	/**
	 * Generates ICMP Time Exceeded packet.
	 * @param ipv4Packet the incoming Ethernet packet for which this Time Exceeded is generated
	 * @param inIface the interface of the incoming packet
	 * @return null on error, ICMP ethernet packet on success
	 */
	public Ethernet genICMPTimeExceeded(Ethernet etherPacket, Iface inIface){

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

		//Dest Mac address is MAC of next hop from lookup in Route and Arp tables for the IP of the source ipv4Packet
		RouteEntry routeEntry = routeTable.lookup(ipv4Packet.getSourceAddress());
		if(routeEntry == null){
			System.out.println("ICMP return failed: route entry for received packet not found");
			return null;
		}

		//get the corresponding MAC for this IP address
		ArpEntry arpEntry = null;	

		if(routeEntry.getGatewayAddress() == 0)
			arpEntry = arpCache.lookup(ipv4Packet.getSourceAddress());
		else
			arpEntry = arpCache.lookup(routeEntry.getGatewayAddress());

		MACAddress nextHopMAC = arpEntry.getMac();
		ether.setDestinationMACAddress(nextHopMAC.toBytes());

		return ether;
		//Send ICMP packet
		//System.out.println("Sending back ICMP " + ether.toString().replace("\n", "\n\t"));
		//sendPacket(ether, inIface);
	}


	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		if(etherPacket.getEtherType() == Ethernet.TYPE_ARP){

		    System.out.println("\nHandling the arp request");
			//handle the ARP Packet
			
			ARP arpPacket = (ARP)etherPacket.getPayload();
			int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
			
			//check for the request
			if(arpPacket.getOpCode() == ARP.OP_REQUEST){
				
				//check if the target IP is the inIface IP
				if(targetIp != inIface.getIpAddress()){
					return ;
				}
			}
			else{
				//The ARP reply was not intended for us
				return;
			}
			
			//Construct the ARP Reply
			Ethernet ether = new Ethernet();
			ARP arpReplyPacket = new ARP();
			
			//Set the fields for the Ethernet packet
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
			arpReplyPacket.setSenderHardwareAddress(IPv4.toIPv4AddressBytes(inIface.getIpAddress()));
			arpReplyPacket.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
			arpReplyPacket.setTargetProtocolAddress(arpPacket.getTargetProtocolAddress());
			
			// Set the ARP Packet as the Ethernet packet payload 
			ether.setPayload(arpReplyPacket);
			
			// Send the reply through the interface through which we received the request
			System.out.println("Before sending the arp reply");
			sendPacket(ether, inIface);
		}
		else if(etherPacket.getEtherType()!= this.IPV4ETHERTYPE){
			//Not IPv4 or ARP - drop the packet
			return;
		}

		IPv4 ipv4Packet = (IPv4)etherPacket.getPayload();

		//check the TTL and send ICMP Time Exceeded message
		if(ipv4Packet.getTtl() == 1){

			Ethernet ether=null;
			if( (ether=genICMPTimeExceeded(etherPacket, inIface)) != null )
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

		//find if the destination address matches one of the interfaces' ip
		Iterator<Iface> ifaceIt = interfaces.values().iterator();
		Iface tIface = null;

		while(ifaceIt.hasNext())
		{
			tIface = ifaceIt.next();
			if(tIface.getIpAddress() == ipv4Packet.getDestinationAddress()){

				Ethernet ether=genICMPTimeExceeded(etherPacket, inIface);
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

		//now forward the packet
		System.out.println("\nLooking to forward the packet");
		RouteEntry routeEntry = routeTable.lookup(ipv4Packet.getDestinationAddress());


		//ICMP Dest Net unreachable
		if(routeEntry == null)
		{
			System.out.println("\nThe look up has failed");
			Ethernet ether=null;
			if( (ether=genICMPTimeExceeded(etherPacket, inIface)) != null )
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


		//get the corresponding MAC for this IP address
		ArpEntry arpEntry = null;

		if(routeEntry.getGatewayAddress() == 0)
			arpEntry = arpCache.lookup(ipv4Packet.getDestinationAddress());
		else
			arpEntry = arpCache.lookup(routeEntry.getGatewayAddress());

		//ICMP Dest Host unreachable
		if(arpEntry==null)
		{
			Ethernet ether=null;
			if( (ether=genICMPTimeExceeded(etherPacket, inIface)) != null )
			{
				ICMP icmp=(ICMP) ether.getPayload().getPayload();
				icmp.setIcmpType((byte)3);
				icmp.setIcmpCode((byte)1);
				sendPacket(ether, inIface);
			}
			return;
		}

		MACAddress nextHopMAC = arpEntry.getMac();

		if( nextHopMAC == null){
			return;
		}
		else{
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
			etherPacket.setDestinationMACAddress(nextHopMAC.toBytes());

			etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());

			sendPacket(etherPacket, routeEntry.getInterface());
		}
		/********************************************************************/
	}
}

