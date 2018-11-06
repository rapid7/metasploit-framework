# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the HSRPHeaders. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'hsrp_header' method (assuming that it is a HSRPHeader object)
  module HSRPHeaderMixin
    def hsrp_version=(v); self.hsrp_header.hsrp_version= v; end
    def hsrp_version; self.hsrp_header.hsrp_version; end
    def hsrp_opcode=(v); self.hsrp_header.hsrp_opcode= v; end
    def hsrp_opcode; self.hsrp_header.hsrp_opcode; end
    def hsrp_state=(v); self.hsrp_header.hsrp_state= v; end
    def hsrp_state; self.hsrp_header.hsrp_state; end
    def hsrp_hellotime=(v); self.hsrp_header.hsrp_hellotime= v; end
    def hsrp_hellotime; self.hsrp_header.hsrp_hellotime; end
    def hsrp_holdtime=(v); self.hsrp_header.hsrp_holdtime= v; end
    def hsrp_holdtime; self.hsrp_header.hsrp_holdtime; end
    def hsrp_priority=(v); self.hsrp_header.hsrp_priority= v; end
    def hsrp_priority; self.hsrp_header.hsrp_priority; end
    def hsrp_group=(v); self.hsrp_header.hsrp_group= v; end
    def hsrp_group; self.hsrp_header.hsrp_group; end
    def hsrp_reserved=(v); self.hsrp_header.hsrp_reserved= v; end
    def hsrp_reserved; self.hsrp_header.hsrp_reserved; end
    def hsrp_addr=(v); self.hsrp_header.hsrp_addr= v; end
    def hsrp_addr; self.hsrp_header.hsrp_addr; end
    def hsrp_vip_readable; self.hsrp_header.hsrp_vip_readable; end
    def hsrp_password_readable; self.hsrp_header.hsrp_password_readable; end
    def hsrp_password; self.hsrp_header.hsrp_password; end
    def hsrp_password=(v); self.hsrp_header.hsrp_password= v; end
    def hsrp_vip; self.hsrp_header.hsrp_vip; end
    def hsrp_vip=(v); self.hsrp_header.hsrp_vip= v; end
  end
end
