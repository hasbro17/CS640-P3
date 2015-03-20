package edu.wisc.cs.sdn.vnet.rt;

import java.util.LinkedList;
import java.util.Queue;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;

public class ARPRequester implements Runnable{
	
	private Ethernet etherARPReq;
	private Iface arpRepIface, arpReqIface;
	private Router rt;
	private boolean done;
	
	private Queue<Ethernet> waiting;
	private Queue<Iface> waitingIfaces;
	private Queue<byte[]> waitingSrcMacs;
	private Ethernet arpReply;

	public ARPRequester(Ethernet etherARPReq, Iface arpReqIface, Router rt) {
		this.etherARPReq=etherARPReq;
		this.arpReqIface=arpReqIface;
		this.rt=rt;
		done=false;		
		waiting=new LinkedList<Ethernet>();
		waitingIfaces=new LinkedList<Iface>();
		waitingSrcMacs=new LinkedList<byte[]>();
	}
	
	public boolean isDone(){
		return done;
	}
	
	//The reply to be set when an ARP reply is recived for this requester by the router
	public void setReply(Ethernet arpReply, Iface arpRepIface){
		this.arpRepIface=arpRepIface;
		this.arpReply=arpReply;
		done=true;
	}
	
	//Add a packet to the queue of waiting packets
	public void add(Ethernet packet, Iface inIface, byte[] srcMac)
	{
		waiting.add(packet);
		waitingIfaces.add(inIface);
		waitingSrcMacs.add(srcMac);
	}

	
	public void run() {
		int count=0;
		//Send 3 ARP requests in one second intervals	
		while(count<3)
		{
			//send ARPrequest
			rt.sendPacket(etherARPReq, arpReqIface);
			
			//wait 1 second, should not be interrupted
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			count++;
			if(done)
				break;
		}
		
		done=true;

		////If the ARP reply made it in time, forward the queued packets to their next hop
		if(arpReply!=null)
		{
			ARP arp=(ARP) arpReply.getPayload();
			while(!waiting.isEmpty())
			{
				Ethernet etherPacket=waiting.poll();
				etherPacket.setDestinationMACAddress(arp.getSenderHardwareAddress());
				rt.sendPacket(etherPacket, arpRepIface);//send the packets forward on the iface the arpReply came in
			}
		}
		//Else reply back with ICMP Dest Host Unreachable to each of the hosts who send a packet for this IP
		else
		{
			while(!waiting.isEmpty())
			{		
				//Get packet, inIface and originalSrcMAC
				Ethernet etherPacket=waiting.poll();
				Iface inIface = waitingIfaces.poll();
				byte[] origSrcMAC = waitingSrcMacs.poll();
				
				//Generate ICMP dest host for each packet
				Ethernet etherICMP= rt.genICMPTimeExceeded(etherPacket,inIface, origSrcMAC);
				ICMP icmp=(ICMP) etherICMP.getPayload().getPayload();
				icmp.setIcmpType((byte)3);
				icmp.setIcmpCode((byte)1);
				
				rt.sendPacket(etherICMP, inIface);
			}
		}
		return;
	}
	
}
