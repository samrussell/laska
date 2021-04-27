class Imm:
    def __init__(self, value):
        self.value = value
    
    def __eq__(self, other):
        return isinstance(other, Imm) and self.value == other.value
    
    def __repr__(self):
        return "Imm(%d)" % self.value