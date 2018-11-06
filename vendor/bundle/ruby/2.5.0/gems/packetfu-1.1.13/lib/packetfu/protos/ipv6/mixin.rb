# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the IPv6Headers. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'ipv6_header' method (assuming that it is a IPv6Header object)
  module IPv6HeaderMixin
    def ipv6_v=(v); self.ipv6_header.ipv6_v= v; end
    def ipv6_v; self.ipv6_header.ipv6_v; end
    def ipv6_class=(v); self.ipv6_header.ipv6_class= v; end
    def ipv6_class; self.ipv6_header.ipv6_class; end
    def ipv6_label=(v); self.ipv6_header.ipv6_label= v; end
    def ipv6_label; self.ipv6_header.ipv6_label; end
    def ipv6_len=(v); self.ipv6_header.ipv6_len= v; end
    def ipv6_len; self.ipv6_header.ipv6_len; end
    def ipv6_next=(v); self.ipv6_header.ipv6_next= v; end
    def ipv6_next; self.ipv6_header.ipv6_next; end
    def ipv6_hop=(v); self.ipv6_header.ipv6_hop= v; end
    def ipv6_hop; self.ipv6_header.ipv6_hop; end
    def ipv6_src=(v); self.ipv6_header.ipv6_src= v; end
    def ipv6_src; self.ipv6_header.ipv6_src; end
    def ipv6_dst=(v); self.ipv6_header.ipv6_dst= v; end
    def ipv6_dst; self.ipv6_header.ipv6_dst; end
    def ipv6_calc_len; self.ipv6_header.ipv6_calc_len; end
    def ipv6_recalc(*v); self.ipv6_header.ipv6_recalc(*v); end
    def ipv6_saddr; self.ipv6_header.ipv6_saddr; end
    def ipv6_saddr=(v); self.ipv6_header.ipv6_saddr= v; end
    def ipv6_daddr; self.ipv6_header.ipv6_daddr; end
    def ipv6_daddr=(v); self.ipv6_header.ipv6_daddr= v; end
    def ipv6_src_readable; self.ipv6_header.ipv6_src_readable; end
    def ipv6_dst_readable; self.ipv6_header.ipv6_dst_readable; end
  end
end
