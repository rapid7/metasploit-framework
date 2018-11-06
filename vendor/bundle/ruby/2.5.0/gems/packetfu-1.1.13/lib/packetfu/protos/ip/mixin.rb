# -*- coding: binary -*-

module PacketFu
  # This Mixin simplifies access to the IPHeaders. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'ip_header' method (assuming that it is a IPHeader object)
  module IPHeaderMixin
    def ip_calc_id; self.ip_header.ip_calc_id ; end
    def ip_calc_len; self.ip_header.ip_calc_len ; end
    def ip_calc_sum; self.ip_header.ip_calc_sum ; end
    def ip_daddr; self.ip_header.ip_daddr ; end
    def ip_daddr=(v); self.ip_header.ip_daddr= v; end
    def ip_dst; self.ip_header.ip_dst ; end
    def ip_dst=(v); self.ip_header.ip_dst= v; end
    def ip_dst_readable; self.ip_header.ip_dst_readable ; end
    def ip_frag; self.ip_header.ip_frag ; end
    def ip_frag=(v); self.ip_header.ip_frag= v; end
    def ip_hl; self.ip_header.ip_hl ; end
    def ip_hl=(v); self.ip_header.ip_hl= v; end
    def ip_hlen; self.ip_header.ip_hlen ; end
    def ip_id; self.ip_header.ip_id ; end
    def ip_id=(v); self.ip_header.ip_id= v; end
    def ip_id_readable; self.ip_header.ip_id_readable ; end
    def ip_len; self.ip_header.ip_len ; end
    def ip_len=(v); self.ip_header.ip_len= v; end
    def ip_proto; self.ip_header.ip_proto ; end
    def ip_proto=(v); self.ip_header.ip_proto= v; end
    def ip_recalc(*args); self.ip_header.ip_recalc(*args) ; end
    def ip_saddr; self.ip_header.ip_saddr ; end
    def ip_saddr=(v); self.ip_header.ip_saddr= v; end
    def ip_src; self.ip_header.ip_src ; end
    def ip_src=(v); self.ip_header.ip_src= v; end
    def ip_src_readable; self.ip_header.ip_src_readable ; end
    def ip_sum; self.ip_header.ip_sum ; end
    def ip_sum=(v); self.ip_header.ip_sum= v; end
    def ip_sum_readable; self.ip_header.ip_sum_readable ; end
    def ip_tos; self.ip_header.ip_tos ; end
    def ip_tos=(v); self.ip_header.ip_tos= v; end
    def ip_ttl; self.ip_header.ip_ttl ; end
    def ip_ttl=(v); self.ip_header.ip_ttl= v; end
    def ip_v; self.ip_header.ip_v ; end
    def ip_v=(v); self.ip_header.ip_v= v; end
  end
end
