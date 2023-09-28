package edu.cauc.UserDefined;

import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;

import java.io.Serial;
import java.util.ArrayList;
import java.util.List;

public final class UserDefinedPacket extends AbstractPacket
{

    @Serial
    private static final long serialVersionUID = 8001811020717409437L;

    private final UserHeader header;

    public static UserDefinedPacket newPacket(byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new UserDefinedPacket(rawData, offset, length);
    }

    private UserDefinedPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        this.header = new UserHeader(rawData, offset, length);
    }
    //构造函数
    UserDefinedPacket(UserBuilder builder) {
        if (builder == null) {
            String sb = "builder: " +
                    builder;
            throw new NullPointerException(sb);
        }

        this.header = new UserHeader(builder);
    }

    @Override
    public UserHeader getHeader() {
        return header;
    }

    @Override
    public UserBuilder getBuilder() {
    return new UserBuilder(this);
}

    public static final class UserBuilder extends AbstractBuilder
    {
        // 类型
        private short User_type;
        // 用户性别
        private byte User_sex;
        // 用户名称
        private int User_name;
        // 用户学号
        private int  User_id;
        // 当前小时数
        private byte Hour;
        // 当前分钟数
        private byte Min;
        // 完成作业数
        private short Homework;

        public UserBuilder(){}

        public UserBuilder(UserDefinedPacket packet)
        {
            this.User_type = packet.header.User_type;
            this.User_sex = packet.header.User_sex;
            this.User_name = packet.header.User_name;
            this.User_id = packet.header.User_id;
            this.Hour = packet.header.Hour;
            this.Min = packet.header.Min;
            this.Homework = packet.header.Homework;
        }

        public UserBuilder User_type(short User_type)
        {
            this.User_type = User_type;
            return this;
        }

        public UserBuilder User_sex(byte User_sex)
        {
            this.User_sex = User_sex;
            return this;
        }

        public UserBuilder User_name(int User_name)
        {
            this.User_name = User_name;
            return this;
        }

        public UserBuilder User_id(int User_id)
        {
            this.User_id = User_id;
            return this;
        }

        public UserBuilder Hour(byte Hour)
        {
            this.Hour = Hour;
            return this;
        }

        public UserBuilder Min(byte Min)
        {
            this.Min = Min;
            return this;
        }

        public UserBuilder Homework(short Homework)
        {
            this.Homework = Homework;
            return this;
        }

        @Override
        public UserDefinedPacket build() {
            return new UserDefinedPacket(this);
        }
    }



    public static final class UserHeader extends AbstractHeader
    {
        // 类型字段
        private final short User_type;
        private static final int TYPE_OFFSET = 0;

        private static final int TYPE_SIZE = 2;

        // 性别
        private final byte User_sex;
        private static final int SEX_OFFSET = TYPE_OFFSET + TYPE_SIZE;
        private static final int SEX_SIZE = 1;

        // 用户名称
        private final int User_name;
        private static final int USER_NAME_OFFSET = SEX_OFFSET + SEX_SIZE;
        private static final int USER_NAME_SIZE = 4;

        // 学号
        private final int User_id;
        private static final int USER_ID_OFFSET = USER_NAME_OFFSET + USER_NAME_SIZE;
        private static final int USER_ID_SIZE = 4;

        // 小时数
        private final byte Hour;
        private static final int HOUR_OFFSET = USER_ID_OFFSET + USER_ID_SIZE;
        private static final int HOUR_SIZE = 1;

        // 分钟数
        private final byte Min;
        private static final int MIN_OFFSET = HOUR_OFFSET + HOUR_SIZE;
        private static final int MIN_SIZE = 1;

        // 完成作业数
        private final short Homework;
        private static final int HOMEWORK_OFFSET = MIN_OFFSET + MIN_SIZE;
        private static final int HOMEWORK_SIZE = 2;

        // 构造函数
        private UserHeader(UserBuilder builder)
        {
            this.User_type = builder.User_type;
            this.User_sex = builder.User_sex;
            this.User_name = builder.User_name;
            this.User_id = builder.User_id;
            this.Hour = builder.Hour;
            this.Min = builder.Min;
            this.Homework = builder.Homework;
        }


        // 从rawdata中获取信息
        UserHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException
        {
            this.User_type = ByteArrays.getShort(rawData , TYPE_OFFSET + offset);
            this.User_sex = ByteArrays.getByte(rawData , SEX_OFFSET + offset);
            this.User_name = ByteArrays.getInt(rawData , USER_NAME_OFFSET + offset);
            this.User_id = ByteArrays.getInt(rawData , USER_ID_OFFSET + offset);
            this.Hour = ByteArrays.getByte(rawData , HOUR_OFFSET + offset);
            this.Min = ByteArrays.getByte(rawData , MIN_OFFSET + offset);
            this.Homework = ByteArrays.getShort(rawData , HOMEWORK_OFFSET + offset);
        }

        public short getUser_type() {
            return this.User_type;
        }

        public byte getUser_sex() {
            return this.User_sex;
        }

        public int getUser_name() {
            return this.User_name;
        }

        public int getUser_id() {
            return this.User_id;
        }

        public byte getHour() {
            return this.Hour;
        }

        public byte getMin() {
            return this.Min;
        }

        public short getHomework() {
            return this.Homework;
        }

        // 存入rawdata信息
        @Override
        protected List<byte[]> getRawFields()
        {
            List<byte[]> rawFields = new ArrayList<byte[]>();
            rawFields.add(ByteArrays.toByteArray(this.User_type));
            rawFields.add(ByteArrays.toByteArray(this.User_sex));
            rawFields.add(ByteArrays.toByteArray(this.User_name));
            rawFields.add(ByteArrays.toByteArray(this.User_id));
            rawFields.add(ByteArrays.toByteArray(this.Hour));
            rawFields.add(ByteArrays.toByteArray(this.Min));
            rawFields.add(ByteArrays.toByteArray(this.Homework));
            return rawFields;
        }
    }
}
