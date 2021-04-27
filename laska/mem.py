class Mem:
    def __init__(self, segment, base, disp):
        self.segment = segment
        self.base = base
        self.disp = disp
    
    def __eq__(self, other):
        return isinstance(other,Mem) and self.segment == other.segment and self.base == other.base and self.disp == other.disp
    
    def __repr__(self):
        return "Mem(%s, %s, %s)" % (self.segment, self.base, self.disp)
    
    def disasm(self):
        return "[%s:%s+%s]" % (self.segment, self.base, self.disp)