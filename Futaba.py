
import copy;

class Futaba():
    def __init__(self):
        self.id = 0x0F;
        self.id_sbus2 = self.id;
        self.id_sbus  = self.id;
        self.header = self.id_sbus2
        self.packet = [];
        for n in range(0, 25):
            self.packet.append(0);
        self.ch17 = 0;
        self.ch18 = 0;
        self.frame_lost = 0;
        self.fail_safe = 0;
        self.slot_0_to_7 = 0x04;
        self.slot_8_to_15 = 0x14;
        self.slot_16_to_23 = 0x24;
        self.slot_24_to_31 = 0x34;

        self.slot_message_dict = {
            self.slot_0_to_7 : "S.BUS Slot0-7",
            self.slot_8_to_15 : "S.BUS Slot8-15",
            self.slot_16_to_23 : "S.BUS Slot16-23",
            self.slot_24_to_31 : "S.BUS Slot24-31",
        };

    def clear_packet(self):
        for n in range(0, 25):
            self.packet.append(0);

    def decode_bytes_from_packet(self, data, packet_index, message):
        self.packet[packet_index] = copy.deepcopy(data);
        data_ch1  = (self.packet[1] | self.packet[2] << 8 & 0x07FF);
        data_ch2  = (self.packet[2] >> 3 | self.packet[3] << 5 & 0x07FF);
        data_ch3  = (self.packet[3] >> 6 | self.packet[4] << 2 | self.packet[5] << 10 & 0x07FF);
        data_ch4  = (self.packet[5] >> 1 | self.packet[6] << 7 & 0x07FF);
        data_ch5  = (self.packet[6] >> 4 | self.packet[7] << 4 & 0x07FF);
        data_ch6  = (self.packet[7] >> 7 | self.packet[8] << 1 | self.packet[9] << 9 & 0x07FF);
        data_ch7  = (self.packet[9] >> 2 | self.packet[10] << 6 & 0x07FF);
        data_ch8  = (self.packet[10] >> 5 | self.packet[11] << 3 & 0x07FF);
        data_ch9  = (self.packet[12] | self.packet[13] << 8 & 0x07FF);
        data_ch10  = (self.packet[13] >> 3 | self.packet[14] << 5 & 0x07FF);
        data_ch11 = (self.packet[14] >> 6 | self.packet[15] << 2 | self.packet[16] << 10 & 0x07FF);
        data_ch12 = (self.packet[16] >> 1 | self.packet[17] << 7 & 0x07FF);
        data_ch13 = (self.packet[17] >> 4 | self.packet[18] << 4 & 0x07FF);
        data_ch14 = (self.packet[18] >> 7 | self.packet[19] << 1 | self.packet[20] << 9 & 0x07FF);
        data_ch15 = (self.packet[20] >> 2 | self.packet[21] << 6 & 0x07FF);
        data_ch16 = (self.packet[21] >> 5 | self.packet[22] << 3 & 0x07FF);
        if packet_index == 2:
            message = "CH1";
            data = data_ch1;
        elif packet_index == 3:
            message = "CH2";
            data = data_ch2;
        elif packet_index == 5:
            message = "CH3";
            data = data_ch3;
        elif packet_index == 6:
            message = "CH4";
            data = data_ch4;
        elif packet_index == 7:
            message = "CH5";
            data = data_ch5;
        elif packet_index == 9:
            message = "CH6";
            data = data_ch6;
        elif packet_index == 10:
            message = "CH7";
            data = data_ch7;
        elif packet_index == 11:
            message = "CH8";
            data = data_ch8;
        elif packet_index == 13:
            message = "CH9";
            data = data_ch9;
        elif packet_index == 14:
            message = "CH10";
            data = data_ch10;
        elif packet_index == 16:
            message = "CH11";
            data = data_ch11;
        elif packet_index == 17:
            message = "CH12";
            data = data_ch12;
        elif packet_index == 18:
            message = "CH13";
            data = data_ch13;
        elif packet_index == 20:
            message = "CH14";
            data = data_ch14;
        elif packet_index == 21:
            message = "CH15";
            data = data_ch15;
        elif packet_index == 22:
            message = "CH16";
            data = data_ch16;
        else:
            data = "";
        return message, data;

    def decode_flags(self, flag_byte):
        #bit order 7:0
        self.ch17 = 0; #7
        self.ch18 = 0; #6
        self.frame_lost = 0; #5
        self.fail_safe = 0; #4
        if (flag_byte & 0x80) & 0x0FF:
            self.ch17 = 1;
        if (flag_byte & 0x40) & 0x0FF:
            self.ch18 = 1;
        if (flag_byte & 0x20) & 0x0FF:
            self.frame_lost = 1;
        if (flag_byte & 0x10) & 0x0FF:
            self.fail_safe = 1;

#                  
#7654321 7654321 7654321 7654321 7654321 7654321 7654321 7654321 
        
#        self.handshake      = 0x21;
#        self.bind_info      = 0x41;
#        self.param_config   = 0x50;
#        self.signal_quality = 0x55;
#        self.telemetry      = 0x80;
#        self.control_data   = 0xCD;

if __name__ == "__main__":
    f = Futaba();
