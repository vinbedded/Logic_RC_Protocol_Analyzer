
class Spektrum():
    def __init__(self):
        self.id = 0xA6;
        self.id_srxl2 = self.id;
        self.id_srxl  = 0xA5;
        self.header = self.id_srxl2;
        
        self.handshake      = 0x21;
        self.bind_info      = 0x41;
        self.param_config   = 0x50;
        self.signal_quality = 0x55;
        self.telemetry      = 0x80;
        self.control_data   = 0xCD;

        ## Debug use only
        #self.id = 0x02;
        #self.bind_info = 0x03
        #self.handshake = 0xA7;
        #self.bind_info = 0xA7;

        self.device_none = 0;
        self.device_remote_rx = 1;
        self.device_rx = 2;
        self.device_flight_controller = 3;
        self.device_esc = 4;
        self.device_reserved = 5;
        self.device_srxl_servo0 = 6;
        self.device_srxl_servo1 = 7;
        self.device_vtx = 8;
        self.device_broacast = 15;
        self.device_type = {
            0 : "No Device Specified",
            1 : "Remote Receiver",
            2 : "Receiver",
            3 : "Flight Controller",
            4 : "ESC",
            5 : "reserved",
            6 : "SRXL Servo",
            7 : "SRXL Servo",
            8 : "VTX",
            15: "Broadcast",
        }
        for n in range(9, 15):
            self.device_type.update({n : "reserved"});

        self.payload_type = {
            self.bind_info : {
                "Request" : {
                    0xEB : "Enter Bind Mode",
                    0xB5 : "Request Bind Status",
                    0xDB : "Bound Data Report",
                    0x5B : "Set Bind Info",
                },
                "Type" : {
                    0x00 : "Not Bound/Exit Bound",
                    0x01 : "DSM2 1024 22ms",
                    0x02 : "DSM2 1024 (MC24)",
                    0x12 : "DSM2 2048 11ms",
                    0xA2 : "DSMX 22ms",
                    0xB2 : "DSMX 11ms",
                    0x63 : "Surgace DSM2 16.5ms",
                    0xE2 : "DSMR 11ms/22ms",
                    0xE4 : "DSMR 5.5ms",
                },
                "Options" : {
                },
            },
            self.param_config : {
                "Request" : {
                    0x50 : "Query Parameter Value",
                    0x57 : "Write Parameter Value",
                },
            },
            self.signal_quality : {
                "Request" : {
                    0x52 : "Request Quality Status",
                    0x53 : "Quality Status Report",
                },
            },
            self.control_data : {
                "Command" : {
                    0x00 : "Channel Data",
                    0x01 : "Failsafe Channel Data",
                    0x02 : "VTX Data",
                    0x03 : "reserved",
                },
            },
        }
        
        self.packet_type = {
            self.handshake : {
                "packet_description" : "Handshake",
                "byte_length" : {
                    "min" : 14,
                    "max" : 14,
                },
                "payload" : {
                    0 : "Send ID",
                    1 : "Dest ID",
                    2 : "Priority",
                    3 : "Baud Rate",
                    4 : "Info",
                    5 : "UID_0",
                    6 : "UID_1",
                    7 : "UID_2",
                    8 : "UID_3",
                },
            },
            self.bind_info : {
                "packet_description" : "Bind Info",
                "byte_length" : {
                    "min" : 21,
                    "max" : 21,
                },
                "payload" : {
                    0 : "Request",
                    1 : "Dest ID",
                    2 : "Type",
                    3 : "Options",
                    4 : "GUID_0",
                    5 : "GUID_1",
                    6 : "GUID_2",
                    7 : "GUID_3",
                    8 : "GUID_4",
                    9 : "GUID_5",
                    10 : "GUID_6",
                    11 : "GUID_7",
                    12 : "UID_0",
                    13 : "UID_1",
                    14 : "UID_2",
                    15 : "UID_3",
                },
            },
            self.param_config : {
                "packet_description" : "Parameter Configuration",
                "byte_length" : {
                    "min" : 14,
                    "max" : 14,
                },
                "payload" : {
                    0 : "Request",
                    1 : "Dest ID",
                    2 : "Param ID",
                    3 : "Param Value",
                },
            },
            self.signal_quality : {
                "packet_description" : "Signal Quality",
                "byte_length" : {
                    "min" : 10,
                    "max" : 10,
                },
                "payload" : {
                    0 : "Request",
                    1 : "AntennaA",
                    2 : "AntennaB",
                    3 : "AntennaL",
                    3 : "AntennaR",
                }
            },
            self.telemetry : {
                "packet_description" : "Telemetry Sensor Data",
                "byte_length" : {
                    "min" : 22,
                    "max" : 22,
                },
                "payload" : {
                    0 : "Dest ID",
                    1 : "Telemetry0",
                    2 : "Telemetry1",
                    3 : "Telemetry2",
                    4 : "Telemetry3",
                    5 : "Telemetry4",
                    6 : "Telemetry5",
                    7 : "Telemetry6",
                    8 : "Telemetry7",
                    9 : "Telemetry8",
                    10 : "Telemetry9",
                    11 : "Telemetry10",
                    12 : "Telemetry11",
                    13 : "Telemetry12",
                    14 : "Telemetry13",
                    15 : "Telemetry14",
                    16 : "Telemetry15",
                },
            },
            self.control_data : {
                "packet_description" : "Control Data",
                "byte_length" : {
                    "min" : 5,
                    "max" : 80,
                },
                "payload" : {
                    0 : "Command",
                    1 : "Reply ID",
                },
            },
        }
        for n in range(2, 80):
            self.packet_type[self.control_data]["payload"].update({n : "Payload%d" % (n)});


    def crc16(self, crc, data):
        crc = crc ^ (data << 8);

        for n in range(0, 8):
            print(n);
            if (crc & 0x8000):
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1;

        return crc;

if __name__ == "__main__":
    spektrum = Spektrum();
    #print(spektrum.packet_type);
    data = spektrum.telemetry;
    print(spektrum.packet_type[data]["packet_description"]);
    print(spektrum.packet_type[data]["payload"][1]);
    packet = [0xFE, 0x08, 0x02, 0x4E, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    computedCRC = 0;
    for n in range(0, len(packet)):
        computedCRC = spektrum.crc16(computedCRC, packet[n]);
    print("0x%0.4X" % computedCRC);
    
