package edu.cauc.UserDefined;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import javax.swing.table.TableRowSorter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Scanner;

public class SendUserDefined
{
    private static final String COUNT_KEY = SendUserDefined.class.getName() + ".count";

    // 设置 COUNT 常量，代表本次捕获数据包的数目
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 2);

    // edu.cauc.packet.readTimeout
    private static final String READ_TIMEOUT_KEY = SendUserDefined.class.getName() + ".readTimeout";

    // 设置读取超时时间 ms
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    // edu.cauc.packet.snaplen
    private static final String SNAPLEN_KEY = SendUserDefined.class.getName() + ".snaplen";

    // 要捕获的最大数据包大小
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    // 自定义协议类型使用eth.type==0x8080作为筛选条件
    private static final EtherType type = new EtherType((short) 0x9898, "自定义协议");

    private static int check_user_type(String s)
    {
        HashMap<String , Integer> map = new HashMap<>();
        map.put("CN" , 0x434E);
        map.put("PC" , 0x5043);
        map.put("OS" , 0x4F53);
        map.put("SE" , 0x5345);
        if(map.containsKey(s)) return map.get(s);
        return -1;
    }

    private static String trans_ascii(String s)
    {
        StringBuilder sb = new StringBuilder(s);
        StringBuilder t = new StringBuilder();
        for (int i = 0; i < sb.length(); i++) {
            char ch = sb.charAt(i);
            t.append(Integer.toHexString((int)ch));
        }
        return t.toString();
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, InterruptedException {
        // 输出有关信息
        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        // 网络接口
        PcapNetworkInterface nif;

        try{
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return ;
        }

        if(nif == null) return ;
        // 输出选择了的网卡信息
        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        /**
         * 这里使用mac帧封装
         */

        // 定义mac帧
        EthernetPacket.Builder ethb = new EthernetPacket.Builder();
        UserDefinedPacket.UserBuilder userBuilder = new UserDefinedPacket.UserBuilder();

        Scanner sc = new Scanner(System.in);
        System.out.println("------自定义输入------");
        System.out.println("目的mac地址：");
        MacAddress DST_MAC_ADDR = MacAddress.getByName(sc.nextLine());
        System.out.println("源mac地址：");
        MacAddress SRC_MAC_ADDR = MacAddress.getByName(sc.nextLine());
        String s = null;
        int user_type = 0;
        while (true)
        {
            System.out.println("计算机网络(CN)、编译原理(PC)、操作系统(OS)、软件工程(SE)，输入对应编号：");
            s = sc.nextLine();
            user_type = check_user_type(s);
            if(user_type != -1) break;
            System.out.println("请重新输入");
        }

        int sex;
        while(true)
        {
            System.out.println("男生使用 1 ， 女生使用 0，输入对应编号：");
            sex = Integer.parseInt(sc.nextLine());
            if(sex != 1 && sex != 0) System.out.println("请重新输入");
            else break;
        }
        System.out.println("请输入名字首字母：");
        String name = trans_ascii(sc.nextLine());
        System.out.println(name);
        System.out.println("请输入学号（类似210340170）：");
        int id = Integer.parseInt(sc.nextLine());
        System.out.println("请输入小时数：");
        byte hour = sc.nextByte();
        System.out.println("请输入分钟数：");
        byte min = sc.nextByte();
        System.out.println("请输入完成作业数：");
        short homework = sc.nextShort();

        // ether src 94:e7:0b:29:71:1f and ether dst ff:ff:ff:ff:ff:ff
        userBuilder
                .User_type((short) user_type)
                .User_sex((byte) sex)
                // XHT
                .User_name(Integer.parseInt(name , 16))
                // 210340170
                .User_id(id)
                // 14:35
                .Hour(hour)
                .Min(min)
                // 10个作业
                .Homework(homework);
        ethb
                .dstAddr(DST_MAC_ADDR)
                .srcAddr(SRC_MAC_ADDR)
                .type(type)
                .payloadBuilder(userBuilder)
                .paddingAtBuild(true);

        PcapHandle sendHandle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        for (int i = 0; i < COUNT; i++) {
            Packet p = ethb.build();
            System.out.println(p);
            sendHandle.sendPacket(p);

            try{
                Thread.sleep(1000);
            } catch (InterruptedException e){
                break;
            }
        }
    }
}
