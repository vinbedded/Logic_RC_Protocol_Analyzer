# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

from Spektrum import *;
from Futaba   import *;
import copy;

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    #my_string_setting = StringSetting()
    #my_number_setting = NumberSetting(min_value=0, max_value=100)
    protocol = ChoicesSetting(choices=("S.Bus",
                                       "S.Bus2",
                                       'SRXL2'))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    #result_types = {
    #    'mytype': {
    #        'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
    #    }
    #}
    result_types = {
        'SRXL2 (SOF)': {
            'format': 'SRXL2 (SOF)'
        },
        "Length": {
            "format" : "Length({{data.input}})",
        },
        "CRC Lo": {
            "format" : "CRC Lo"
        },
        "CRC Hi": {
            "format" : "CRC Hi"
        },
    }
    for n in range(0, 200):
        result_types.update({
            "Data%d" % n : {
                'format' : "Data%d" % (n),
            }
        });

    for n in range(1, 20):
        result_types.update({
            "CH%d" % n: {
                "format" : 'CH%d={{data.input_type}}' % n,
            }
        });
    result_types.update({
        "S.BUS" : {
            "format" : '{{data.input_type}}'
        },
        "S.BUS (SOF)" : {
            "format" : "S.BUS (SOF)",
        },
        "CH17_CH18_FL_FS" : {
            "format" : 'CH17={{data.ch17}},CH18={{data.ch18}},FL={{data.frame_lost}},FS={{data.fail_safe}}',
            #"format" : '{{data.input_type}}',
        },
        "S.BUS Slot0-7" : {
            "format" : "Slots 0 to 7",
        },
        "S.BUS Slot8-15" : {
            "format" : "Slots 8 to 15",
        },
        "S.BUS Slot16-23" : {
            "format" : "Slots 16 to 23",
        },
        "S.BUS Slot24-31" : {
            "format" : "Slots 24 to 31",
        },
        "RX V" : {
            "format" : "RX Voltage",
        },
        "Telemetry" : {
            "format" : "",
        },
        "Nothing" : {
            "format" : "",
        },
    })
    
    Spektrum = Spektrum();
    Futaba = Futaba();
    for packet_type in Spektrum.packet_type:
        #print(packet_type);
        cur_type = Spektrum.packet_type[packet_type]["packet_description"];
        result_types.update({
            cur_type : {
                'format' : '%s' % cur_type
            }
        });
        for payload in Spektrum.packet_type[packet_type]["payload"]:
            payload =  Spektrum.packet_type[packet_type]["payload"][payload];
            result_types.update({
                payload : {
                    'format' : "%s" % payload,
                }
            }); 

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        print("Settings:",
              #self.my_string_setting,
              #self.my_number_setting,
              self.protocol)

        self.spektrum = Spektrum();
        self.futaba   = Futaba();
        self.sof = False;
        self.eof = False;
        self.data_length = 0;
        self.data_index  = 0;
        self.packet_type = "";
        self.packet_index = 0;
        self.current_slots = 0;
        self.slot_data_index = 0;
        self.current_slot_id = 0;
        self.slot_value = 0;

    def decode_futaba(self, frame: AnalyzerFrame):
        
        data = int.from_bytes(frame.data['data'], "big");
        
        message = "S.BUS"
        input_type = "";
        valid_slot = False;
        
        if (self.current_slots in [0x04, 0x14, 0x24, 0x34]) and (not self.sof) and (data != self.futaba.header):
            if self.slot_data_index == 0:
                if data == self.futaba.sbus2_slot_id[0]:
                    message = "RX V";
                else:
                    message = "Telemetry";
                self.current_slot_id = data;
                valid_slot = True;
            elif self.slot_data_index == 1:
                valid_slot = True;
                message = "Nothing";
                self.slot_value = data << 8;
                #self.slot_value = copy.deepcopy(data);
            elif self.slot_data_index == 2:
                valid_slot = True;
                message = "S.BUS";
                self.slot_value = self.slot_value | data;
                #self.slot_value = (data << 8) | self.slot_value;
                data = self.slot_value;
            elif self.slot_data_index == 3:
                if data not in self.futaba.sbus2_slot_id:
                    valid_slot = False;
                    self.current_slots = 0;
                    self.slot_data_index = 0;
                    self.current_slot_id = 0;
                    self.slot_value = 0;
                else:
                    message = "Telemetry";
                    self.slot_data_index = 0;
                    self.current_slot_id = data;
            #print(self.slot_data_index, data);

            if valid_slot:
                self.slot_data_index+=1;
                return AnalyzerFrame(message, frame.start_time, frame.end_time, {"input_type" : data})
            else:
                message = "S.BUS";
        else:
            valid_slot = False;
            self.current_slots = 0;
            self.slot_data_index = 0;
            self.current_slot_id = 0;
            self.slot_value = 0;
            
        
        if self.packet_index == 0 and (data == self.futaba.header):
            self.sof = True;
            message = "S.BUS (SOF)";
            print("%s (SoF)" % (message));

        if not self.sof:
            return;

        if (self.packet_index >= 1) and (self.packet_index <= 22):
            #print(self.packet_index);
            message, data = self.futaba.decode_bytes_from_packet(data, self.packet_index, message);

        if self.packet_index == 23:
            #message = "CH17_CH18_FL_FS";
            self.futaba.decode_flags(data);
            print("Flags: CH17=%d,CH18=%d,FrmLost=%d,FailSafe=%d" % (self.futaba.ch17, self.futaba.ch18, self.futaba.frame_lost, self.futaba.fail_safe));
            #input_type = "CH17=%d,CH18=%d,FL=%d,FS=%d" % (self.futaba.ch17, self.futaba.ch18, self.futaba.frame_lost, self.futaba.fail_safe);

        if self.packet_index == 24:
            if self.protocol == "S.Bus2":
                message = self.futaba.slot_message_dict[data];
                self.current_slots = data;
            else:
                self.current_slots = 0;
                message = "";
            print(message);
            self.eof = True;

        if self.eof:
            self.packet_index = 0;
            self.data_length = 0;
            self.data_index  = 0;
            self.sof = False;
            self.eof = False;
            self.futaba.clear_packet();
        elif self.sof:
            self.packet_index += 1;

        #return AnalyzerFrame(message, frame.start_time, frame.end_time, {"S.BUS" : frame.data['data']})
        if self.packet_index == 23:
            #return AnalyzerFrame(message, frame.start_time, frame.end_time, {"ch17" : self.futaba.ch17,
            #                                                                 "ch18" : self.futaba.ch18,
            #                                                                 "frame_lost" : self.futaba.frame_lost,
            #                                                                 "fail_safe"  : self.futaba.fail_safe});
            #return AnalyzerFrame(message, frame.start_time, frame.end_time, {"input_type" : self.futaba.ch17,
            #                                                                 "input_type" : self.futaba.ch18,
            #                                                                 "input_type" : self.futaba.frame_lost,
            #                                                                 "input_type"  : self.futaba.fail_safe});
            #return AnalyzerFrame(message, frame.start_time, frame.end_time, {"input_type" : input_type})
            return AnalyzerFrame(message, frame.start_time, frame.end_time, {"input_type" : data})
        else:
            return AnalyzerFrame(message, frame.start_time, frame.end_time, {"input_type" : data})
            
        
    def decode_spektrum(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        data = int.from_bytes(frame.data['data'], "big");

        message = "";
        if self.packet_index == 0 and (data == self.spektrum.id):
            self.sof = True;
            message = "SRXL2 (SOF)";
            #print("%s (SoF)" % (message));

        if not self.sof:
            return;
        
        if self.packet_index == 1:
            self.packet_type = copy.deepcopy(data);
            try:
                message = self.spektrum.packet_type[data]["packet_description"]
                print(message);
            except:
                message = "Packet Types"
                self.packet_index = 0;
                self.data_length = 0;
                self.data_index  = 0;
                self.sof = False;
                self.eof = False;
                print("Undocumented Packet");
                return

        if self.packet_index == 2:
            self.data_length = copy.deepcopy(data);
            message = "Length";
            #print("%s (%d) = %d" % (message, self.packet_index, self.data_length));

        if (self.packet_index >= 3) and (self.packet_index < self.data_length+3):
            try:
                message = self.spektrum.packet_type[self.packet_type]["payload"][self.data_index];
            except:
                message = "Data%d" % (self.data_index);
            
            self.data_index += 1;

        if self.packet_index == (self.data_length-2):
            message = "CRC Hi";
            
        if self.packet_index == (self.data_length-1):
            message = "CRC Lo";
            self.eof = True;

        if self.eof:
            self.packet_index = 0;
            self.data_length = 0;
            self.data_index  = 0;
            self.sof = False;
            self.eof = False;
        elif self.sof:
            self.packet_index += 1;
            

        # Return the data frame itself
        return AnalyzerFrame(message, frame.start_time, frame.end_time, {"SRXL2" : frame.data['data']})
        #return AnalyzerFrame("", frame.start_time, frame.end_time, {message : data});
        #return AnalyzerFrame(message, frame.start_time, frame.end_time, None);
        #return AnalyzerFrame(message, frame.start_time, frame.end_time, {message : str(data)});
        
    def decode(self, frame: AnalyzerFrame):
        if self.protocol in ["SRXL2"]:
            return self.decode_spektrum(frame);
        elif self.protocol in ["S.Bus", "S.Bus2"]:
            return self.decode_futaba(frame);
