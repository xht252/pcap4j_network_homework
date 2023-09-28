package edu.cauc.SendPacket;

import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SendARP
{

    private static final String COUNT_KEY = SendARP.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

    private static final String READ_TIMEOUT_KEY = SendARP.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = SendARP.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName("94-E7-0B-29-71-1F");

    public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
        // 输出一些信息
        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        PcapNetworkInterface nif;
        try {
            // 选择网卡
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        // 没有网卡直接返回
        if (nif == null) return;

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        Scanner sc = new Scanner(System.in);
        System.out.println("请输入源mac地址：");
        MacAddress src_mac = MacAddress.getByName(sc.nextLine());
        System.out.println("请输入目的mac地址：");
        MacAddress dst_mac = MacAddress.getByName(sc.nextLine());
        System.out.println("请输入源ip地址：");
        String src_ip = sc.nextLine();
        System.out.println("请输入目的ip地址：");
        String dst_ip = sc.nextLine();


        PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        PcapHandle sendHandle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        ExecutorService pool = Executors.newSingleThreadExecutor();

        try {

            ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
            try {
                arpBuilder
                        .hardwareType(ArpHardwareType.ETHERNET)
                        .protocolType(EtherType.IPV4) // 协议类型为 IPV4
                        .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES) // MAC 长度
                        .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES) // IP 长度
                        .operation(ArpOperation.REQUEST) // ARP 类型为: 请求
                        .srcHardwareAddr(src_mac) // 源 MAC
                        .srcProtocolAddr(InetAddress.getByName(src_ip)) // 源 IP
                        .dstHardwareAddr(dst_mac)
                        // 目的 IP
                        .dstProtocolAddr(InetAddress.getByName(dst_ip));
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException(e); // 参数错误异常
            }

            EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
            etherBuilder
                    .dstAddr(dst_mac)
                    .srcAddr(src_mac)
                    .type(EtherType.ARP) // 帧类型
                    .payloadBuilder(arpBuilder) // 由于 ARP 请求是包含在帧里的, 故需要做一个 payload
                    .paddingAtBuild(true);

            for (int i = 0; i < COUNT; i++) {
                Packet p = etherBuilder.build();
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
