package edu.cauc.AnalysePacket;

import edu.cauc.UserDefined.UserDefinedPacket;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class AnalyseProtocolFunction
{
    private static String change(int x)
    {
        HashMap<Integer , String> map = new HashMap<>();
        map.put(0x434E , "CN");
        map.put(0x5043 , "PC");
        map.put(0x4F53 , "OS");
        map.put(0x5345 , "SE");
        if(map.containsKey(x)) return map.get(x);
        return "Unknown";
    }

    private static String change_sex(int x)
    {
        if(x == 1) return "男";
        return "女";
    }

    private static String change_name(int x)
    {
        StringBuilder sb = new StringBuilder();
        while(x >= 16)
        {
            sb.append(Integer.toHexString(x % 16));
            x /= 16;
        }
        sb.append(Integer.toHexString(x));

        if(sb.length() == 8) sb.reverse();
        else
        {
            int n = sb.length();
            sb.append("0".repeat(Math.max(0, 8 - n)));
            sb.reverse();
        }
        StringBuilder res = new StringBuilder();
        for (int i = 0; i < sb.length(); i += 2)
        {
            int y = Integer.valueOf(sb.substring(i , i + 2) , 16);
            res.append((char)y);
        }

        return res.toString();
    }

    private static String change_hex(int x)
    {
        StringBuilder res = new StringBuilder("0x");
        ArrayList<String> hex = new ArrayList<>();
        while(x >= 16)
        {
            hex.add(Integer.toHexString(x % 16));
            x /= 16;
        }
        hex.add(Integer.toHexString(x));
        if(hex.size() == 1) return "0x0000";

        for(int i = hex.size() - 1;i >= 0;i --)
            res.append(hex.get(i));
        return res.toString();
    }

    public static EthernetPacket MacAnalyse(PcapPacket packet)
    {
        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        System.out.println("--------------mac协议解析---------------");
        System.out.println("源mac：" + ethernetPacket.getHeader().getSrcAddr());
        System.out.println("目的mac：" + ethernetPacket.getHeader().getDstAddr());
        System.out.println("协议：" + ethernetPacket.getHeader().getType());
        return ethernetPacket;
    }

    public static Boolean UserDefinedAnalyse(PcapPacket packet , EthernetPacket ep) throws IllegalRawDataException {
        // 用户自定义协议基于mac，因此只需要得到mac的payload即可
        // UserDefinedPacket up = packet.get(UserDefinedPacket.class);
        UserDefinedPacket up = UserDefinedPacket.newPacket(ep.getPayload().getRawData() , 0 , 5);
        int type = up.getHeader().getUser_type();
        if(change(type).equals("Unknown"))
        {
            System.out.println("该报文不是用户自定义");
            return false;
        }
        System.out.println("--------------用户自定义协议解析---------------");
        System.out.println("类型：0x" + Integer.toHexString(type) + "(" + change(type) + ")");
        System.out.println("性别：" + change_sex(up.getHeader().getUser_sex()));
        System.out.println("用户名：" + change_name(up.getHeader().getUser_name()));
        System.out.println("学号：" + up.getHeader().getUser_id());
        System.out.format("当前时间：%02d:%02d\n" , up.getHeader().getHour() , up.getHeader().getMin());
        System.out.println("完成作业数：" + up.getHeader().getHomework() + "个");
        return true;
    }

    public static void ARPAnalyse(PcapPacket packet , EthernetPacket ep) throws IllegalRawDataException {
        ArpPacket arp = packet.get(ArpPacket.class);
        System.out.println("-----------ARP协议------------");
        System.out.println("硬件类型：" + arp.getHeader().getHardwareType());
        System.out.println("协议类型：" + arp.getHeader().getProtocolType());
        System.out.println("Mac长度：" + arp.getHeader().getHardwareAddrLengthAsInt());
        System.out.println("协议长度：" + arp.getHeader().getProtocolAddrLengthAsInt());
        System.out.println("ARP类型：" + arp.getHeader().getOperation());
        System.out.println("源Mac地址：" + arp.getHeader().getSrcHardwareAddr());
        System.out.println("目的Mac地址：" + arp.getHeader().getDstHardwareAddr());
        System.out.println("源协议地址：" + arp.getHeader().getSrcProtocolAddr());
        System.out.println("目的协议地址：" + arp.getHeader().getDstProtocolAddr());
    }

    private static void normalIpv4(IpV4Packet ipv4)
    {
        System.out.println("-----------Ipv4协议------------");
        System.out.println("版本：" + ipv4.getHeader().getVersion());
        System.out.println("首部长度：" + ipv4.getHeader().getIhlAsInt());
        System.out.println("服务：" + ipv4.getHeader().getTos());
        System.out.println("总长度：" + ipv4.getHeader().getTotalLengthAsInt());
        System.out.println("标识：" + ipv4.getHeader().getIdentificationAsInt());
        System.out.println("DF不要分片（为1不能分片）：" + ipv4.getHeader().getDontFragmentFlag());
        System.out.println("MF多分片（为1分片）：" + ipv4.getHeader().getMoreFragmentFlag());
        System.out.println("offset分片偏移：" + ipv4.getHeader().getFragmentOffset());
        System.out.println("协议：" + ipv4.getHeader().getProtocol());
        System.out.println("源ip地址：" + ipv4.getHeader().getSrcAddr());
        System.out.println("目的ip地址：" + ipv4.getHeader().getDstAddr());
        System.out.println("首部校验和：" + change_hex(ipv4.getHeader().getHeaderChecksum()));
    }

    private static void normalTCP(PcapPacket packet) throws IllegalRawDataException {
        // tcp and ether src 94:e7:0b:29:71:1f and ether dst ff:ff:ff:ff:ff:ff
        System.out.println("-----------TCP协议------------");
        TcpPacket tcp = packet.get(TcpPacket.class);
        System.out.println("源端口：" + tcp.getHeader().getSrcPort());
        System.out.println("目的端口：" + tcp.getHeader().getDstPort());
        System.out.println("序号：" + tcp.getHeader().getSequenceNumber());
        System.out.println("确认号：" + tcp.getHeader().getAcknowledgmentNumber());
        System.out.println("数据偏移量：" + tcp.getHeader().getDataOffsetAsInt());
        System.out.println("ack：" + tcp.getHeader().getAck());
        System.out.println("Fin：" + tcp.getHeader().getFin());
        System.out.println("Psh：" + tcp.getHeader().getPsh());
        System.out.println("Rst：" + tcp.getHeader().getRst());
        System.out.println("Syn：" + tcp.getHeader().getSyn());
        System.out.println("Urg：" + tcp.getHeader().getUrg());
        System.out.println("窗口大小：" + tcp.getHeader().getWindowAsInt());
        System.out.println("数据：" + Arrays.toString(tcp.getHeader().getPadding()));
    }
    private static void normalUDP(PcapPacket packet){
        System.out.println("-----------UDP协议------------");
        UdpPacket udp = packet.get(UdpPacket.class);
        System.out.println("源端口：" + udp.getHeader().getSrcPort());
        System.out.println("目的端口：" + udp.getHeader().getDstPort());
        System.out.println("总长度：" + udp.getHeader().getLengthAsInt());
    }

    public static void IpAnalyse(PcapPacket packet , EthernetPacket ep) throws IllegalRawDataException
    {
        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        normalIpv4(ipv4);
        if(ipv4.getHeader().getProtocol() == IpNumber.TCP) normalTCP(packet);
        else if(ipv4.getHeader().getProtocol() == IpNumber.UDP) normalUDP(packet);
    }
}
