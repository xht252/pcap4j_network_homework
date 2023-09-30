// 单独ipv4
package edu.cauc.SendPacket;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SendIp
{
    private static final String COUNT_KEY = SendIp.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 4);

    private static final String READ_TIMEOUT_KEY = SendIp.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = SendIp.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    public static final IpNumber XHT = new IpNumber((byte)-20, "XHT");

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

//        System.out.println(Arrays.toString(SrcIp));
        // 输出一些信息
        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        PcapNetworkInterface nif;
        try{
            // 选择网卡
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return ;
        }

        // 没有网卡直接返回
        if(nif == null) return ;

        // ip and ether src 94:e7:0b:29:71:1f and ether dst ff:ff:ff:ff:ff:ff
        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        Scanner sc = new Scanner(System.in);
        System.out.println("请输入源ip地址: ");
        String SrcIp = sc.nextLine();

        System.out.println("请输入目的ip地址: ");
        String DisIp = sc.nextLine();

        System.out.println("请输入源mac地址: ");
        MacAddress src_mac = MacAddress.getByName(sc.nextLine());

        System.out.println("请输入目的mac地址");
        MacAddress dst_mac = MacAddress.getByName(sc.nextLine());


        // 混杂模式的网卡头部
        PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        PcapHandle sendHandle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        ExecutorService pool = Executors.newSingleThreadExecutor();

        try {
            IpV4Packet.Builder ipv4Builder = new IpV4Packet.Builder();
            try
            {
                ipv4Builder
                        .version(IpVersion.IPV4)
                        .tos(IpV4Rfc1349Tos.newInstance((byte)0))
                        .protocol(XHT)
                        .srcAddr((Inet4Address) Inet4Address.getByName(SrcIp))
                        .dstAddr((Inet4Address) Inet4Address.getByName(DisIp))
                        .totalLength((short) 100)
                        .dontFragmentFlag(true)
                        .correctLengthAtBuild(true)
                        .correctChecksumAtBuild(true);
            } catch (UnknownHostException e) {
                throw new RuntimeException(e);
            }


            EthernetPacket.Builder ethb = new EthernetPacket.Builder();
            ethb
                    .dstAddr(dst_mac)
                    .srcAddr(src_mac)
                    .type(EtherType.IPV4)
//                  .payloadBuilder(arpBuilder)
                    .payloadBuilder(ipv4Builder)
                    .paddingAtBuild(true);

            for (int i = 0;i < COUNT;i ++)
            {
                Packet p = ethb.build();
                System.out.println(p);
                sendHandle.sendPacket(p);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    break;
                }
            }

        } finally {
            if (handle.isOpen()) {
                handle.close();
            }
            if (sendHandle.isOpen()) {
                sendHandle.close();
            }
            if (!pool.isShutdown()) {
                pool.shutdown();
            }
        }
    }
}
