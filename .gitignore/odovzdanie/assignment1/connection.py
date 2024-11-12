
class Connection:
    def __init__(self):
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.state = "CLOSED"
        self.packets = []