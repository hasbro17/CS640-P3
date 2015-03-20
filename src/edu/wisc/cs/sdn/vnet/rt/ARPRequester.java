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
		// TODO Auto-generated constructor stub
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
	
	public void setReply(Ethernet arpReply, Iface arpRepIface){
		this.arpRepIface=arpRepIface;
		this.arpReply=arpReply;
		done=true;
	}
	
	public void add(Ethernet packet, Iface inIface, byte[] srcMac)
	{
		waiting.add(packet);
		waitingIfaces.add(inIface);
		waitingSrcMacs.add(srcMac);
	}

	//Send 3 ARP requests in one second intervals
	public void run() {
		int count=0;
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
		System.out.println("Requester thread finished sending requests");
		////Then the reply made it in time, forward the queued packets to their destination
		if(arpReply!=null)
		{
			System.out.println("Requester thread sending queued packets to correct destinations");
			ARP arp=(ARP) arpReply.getPayload();
			while(!waiting.isEmpty())
			{
				Ethernet etherPacket=waiting.poll();
				etherPacket.setDestinationMACAddress(arp.getSenderHardwareAddress());
				rt.sendPacket(etherPacket, arpRepIface);//send the packets forward on the iface the arpReply came in
			}
		}
		//Reply back with ICMP Dest Host Unreachable to each of the hosts
		else
		{
			System.out.println("Requester thread sending back ICMP for queued packets");
			while(!waiting.isEmpty())
			{
				
				//Get packet and the iface it came in on
				Ethernet etherPacket=waiting.poll();
				Iface inIface = waitingIfaces.poll();
				byte[] origSrcMAC = waitingSrcMacs.poll();
				System.out.println("\nFor packet: "+etherPacket.toString());
				//Generate ICMP dest host for each packet
				Ethernet etherICMP= rt.genICMPTimeExceeded(etherPacket,inIface, origSrcMAC);
				//Fix ether
				//FIXME: Cannot generate ICMP timeout like this, set destination MAC address to src MAC address of packet
				ICMP icmp=(ICMP) etherICMP.getPayload().getPayload();
				icmp.setIcmpType((byte)3);
				icmp.setIcmpCode((byte)1);
				
				System.out.println("\nRequester sending back ICMP packet: "+ etherICMP.toString());
				System.out.println("\nRequester sending back on Iface: "+ inIface.toString());
				
				rt.sendPacket(etherICMP, inIface);
			}
		}
		
		return;
	}

}
