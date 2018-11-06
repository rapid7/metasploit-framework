# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the ICMPHeaders. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'icmp_header' method (assuming that it is a ICMPHeader object)
  module ICMPHeaderMixin
    def icmp_type=(v); self.icmp_header.icmp_type= v; end
    def icmp_type; self.icmp_header.icmp_type; end
    def icmp_code=(v); self.icmp_header.icmp_code= v; end
    def icmp_code; self.icmp_header.icmp_code; end
    def icmp_sum=(v); self.icmp_header.icmp_sum= v; end
    def icmp_sum; self.icmp_header.icmp_sum; end
    def icmp_calc_sum; self.icmp_header.icmp_calc_sum; end
    def icmp_recalc(*v); self.icmp_header.icmp_recalc(*v); end
    def icmp_sum_readable; self.icmp_header.icmp_sum_readable; end
  end
end

