# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the UDPHeaders. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'udp_header' method (assuming that it is a UDPHeader object)
  module UDPHeaderMixin
    def udp_src=(v); self.udp_header.udp_src= v; end
    def udp_src; self.udp_header.udp_src; end
    def udp_dst=(v); self.udp_header.udp_dst= v; end
    def udp_dst; self.udp_header.udp_dst; end
    def udp_len=(v); self.udp_header.udp_len= v; end
    def udp_len; self.udp_header.udp_len; end
    def udp_sum=(v); self.udp_header.udp_sum= v; end
    def udp_sum; self.udp_header.udp_sum; end
    def udp_calc_len; self.udp_header.udp_calc_len; end
    def udp_recalc(*v); self.udp_header.udp_recalc(*v); end
    def udp_sport; self.udp_header.udp_sport; end
    def udp_sport=(v); self.udp_header.udp_sport= v; end
    def udp_dport; self.udp_header.udp_dport; end
    def udp_dport=(v); self.udp_header.udp_dport= v; end
    def udp_sum_readable; self.udp_header.udp_sum_readable; end
  end
end

