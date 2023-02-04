class Futaba():
    def __init__(self):
        self.id = 0x0F;
        self.id_sub2 = self.id; #FIXME
        self.id_sbus  = self.id;
        self.header = self.id_srxl2;
        
#        self.handshake      = 0x21;
#        self.bind_info      = 0x41;
#        self.param_config   = 0x50;
#        self.signal_quality = 0x55;
#        self.telemetry      = 0x80;
#        self.control_data   = 0xCD;

if __name__ == "__main__":
    f = Futaba();
