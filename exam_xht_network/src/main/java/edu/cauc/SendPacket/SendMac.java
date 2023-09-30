package edu.cauc.SendPacket;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.util.Scanner;

/**
 * 模拟发送数据包
 */
public class SendMac
{
    // 获取包名和类名 edu.cauc.packet.count
    private static final String COUNT_KEY = SendMac.class.getName() + ".count";

    // 设置 COUNT 常量，代表本次捕获数据包的数目
    private static final int COUNT = Integer.getInteger(COUNT_KEY , 2);

    // edu.cauc.packet.readTimeout
    private static final String READ_TIMEOUT_KEY = SendMac.class.getName() + ".readTimeout";

    // 设置读取超时时间 ms
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    // edu.cauc.packet.snaplen
    private static final String SNAPLEN_KEY = SendMac.class.getName() + ".snaplen";

    // 要捕获的最大数据包大小
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    // 源 MAC 地址本机活跃网卡 MAC 地址

    // 自定义协议类型使用eth.type==0x8080作为筛选条件
    private static final EtherType type = new EtherType((short)0x114514 , "");

    /**
     * @param args
     * @throws PcapNativeException
     * 在Java程序中处理底层pcap操作可能出现的错误，例如打开网络接口失败、设置过滤器失败等
     * @throws NotOpenException
     * 用于表示在未打开网络接口的情况下执行pcap操作时发生的错误
     */
    public static void main(String[] args) throws PcapNativeException , NotOpenException
    {
        // 输出关于类的信息
        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        // pcap网络接口
        PcapNetworkInterface nif;

        try {
            // 选择网络接口 调用了已经封装好的命令行网卡选择函数
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return ;
        }

        if(nif == null) return ;

        // 输出选择了的网卡信息，其中 nifName 为 网卡标识，nifDescription 为 网卡显示名称
        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        /**
         * 广播模式、多播传送、直接模式、混杂模式
         * 广播和直接是网卡的基本模式或称为缺省模式 NONPROMISCUOUS 0
         * 混杂模式 PROMISCUOUS 1
         */
        PcapHandle sendHandle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        try {
            // 核心代码构建操作帧
            EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
            Scanner sc = new Scanner(System.in);
            System.out.println("请输入源mac地址：");
            MacAddress SRC_MAC_ADDR = MacAddress.getByName(sc.nextLine());

            System.out.println("请输入目的mac地址：");
            MacAddress DST_MAC_ADDR = MacAddress.getByName(sc.nextLine());
            // 自定义输入信息
            String payload = null;
            System.out.println("请输入带输入的数据：");
            if(sc.hasNext()) payload = sc.nextLine();

            System.out.println("请输入类型：");
            short y = (short) Integer.parseInt(sc.nextLine() , 16);
            EtherType et = new EtherType(y , "");


            sc.close();

            assert payload != null;
            etherBuilder
                    .dstAddr(DST_MAC_ADDR) // 目的mac地址 以太广播地址
                    .srcAddr(SRC_MAC_ADDR) // 源mac地址
                    .type(et)
                    // 自定义数据
                    // 32 31 30 33 34 30 31 37 30 20 58 48 54 20 48 65 6c 6c 6f 20 45 74 68 65 72 21 21 21
                    // 50 49 48 51 52 48 49 55 48 32 88 72 84 32 72 101 108 111 32 69 116 104 101 114 33 33 33
                    // 2 1 0 3 4 0 1 7 0   X H T   H e l l o   E t h e r ! ! !
                    // .payloadBuilder(new UnknownPacket.Builder().rawData(
                    // ("210340170 XHT Hello Ether!!!").getBytes()))
                    .payloadBuilder(new UnknownPacket.Builder().rawData((payload).getBytes()))
                    // 是否填充至以太网的最小帧长, 必须为 true, 否则对方不会接受请求
                    .paddingAtBuild(true);

            // 这里设置2个请求
            for(int i = 0;i < COUNT;i ++)
            {
                Packet p = etherBuilder.build();
                // 输出包的信息
                System.out.println(p);
                // 发送包
                sendHandle.sendPacket(p);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    break;
                }
            }
        } finally {
            if(sendHandle.isOpen()) sendHandle.close();
        }
    }
}
