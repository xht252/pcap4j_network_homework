package edu.cauc.AnalysePacket;

import edu.cauc.UserDefined.UserDefinedPacket;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.NifSelector;

import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;

public class Analyse
{
    private static final String COUNT_KEY = Analyse.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, -1);

    // 等待读取数据包的时间（以毫秒为单位）, 必须非负 ,其中 0 代表一直等待直到抓到包为止
    private static final String READ_TIMEOUT_KEY = Analyse.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    // 要捕获的最大数据包大小（以字节为单位）
    private static final String SNAPLEN_KEY = Analyse.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static int check(EthernetPacket ep)
    {
        Packet.Header h = ep.getPayload().getHeader();
        String s = String.valueOf(h.getClass());
        int idxIpv4 = s.indexOf("IpV4"); // 标识为 1
        int idxARP = s.indexOf("Arp"); // 标识为2
        if(idxIpv4 != -1) return 1;
        else if(idxARP != -1) return 2;
        return 3;
    }


    public static void main(String[] args)  throws PcapNativeException, NotOpenException
    {
        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        PcapNetworkInterface nif;
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if(nif == null) return ;

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");
        final PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        Scanner sc = new Scanner(System.in);
        String filter;
        while (true)
        {
            System.out.println("请输入过滤器条件：");
            filter = sc.nextLine();
            try {
                handle.setFilter(filter , BpfProgram.BpfCompileMode.OPTIMIZE);
                break;
            } catch (PcapNativeException | NotOpenException e) {
                System.out.println("请重新输入");
            }
        }


        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(PcapPacket Packet)
            {
                try {
                    StringBuilder sb = new StringBuilder();
                    sb.append("-".repeat(50));
                    sb.append("\n");
                    System.out.println(sb);
                    /**
                     * MacAnalyse 解析mac包
                     * UserDefinedAnalyse 解析用户定义包
                     * ARPAnalyse 解析ARP
                     * IpAnalyse 解析Ip
                     */
                    EthernetPacket ep = AnalyseProtocalFunction.MacAnalyse(Packet);
                    boolean flag = AnalyseProtocalFunction.UserDefinedAnalyse(Packet , ep);
                    int idx = check(ep);
                    if(idx == 1 && !flag) // ipv4
                    {
                        AnalyseProtocalFunction.IpAnalyse(Packet , ep);
                        System.out.println(sb);
                    }
                    else if(idx == 2 && !flag) // Arp
                    {
                        AnalyseProtocalFunction.ARPAnalyse(Packet , ep);
                        System.out.println(sb);
                    }
                } catch (IllegalRawDataException e) {
                    throw new RuntimeException(e);
                }
            }
        };

        try {
            handle.loop(COUNT, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
