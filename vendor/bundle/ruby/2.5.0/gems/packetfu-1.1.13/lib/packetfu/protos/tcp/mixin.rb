# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the TCPHeaders. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'tcp_header' method (assuming that it is a TCPHeader object)
  module TCPHeaderMixin
    def tcp_src=(v); self.tcp_header.tcp_src= v; end
    def tcp_src; self.tcp_header.tcp_src; end
    def tcp_dst=(v); self.tcp_header.tcp_dst= v; end
    def tcp_dst; self.tcp_header.tcp_dst; end
    def tcp_seq=(v); self.tcp_header.tcp_seq= v; end
    def tcp_seq; self.tcp_header.tcp_seq; end
    def tcp_ack=(v); self.tcp_header.tcp_ack= v; end
    def tcp_ack; self.tcp_header.tcp_ack; end
    def tcp_win=(v); self.tcp_header.tcp_win= v; end
    def tcp_win; self.tcp_header.tcp_win; end
    def tcp_sum=(v); self.tcp_header.tcp_sum= v; end
    def tcp_sum; self.tcp_header.tcp_sum; end
    def tcp_urg=(v); self.tcp_header.tcp_urg= v; end
    def tcp_urg; self.tcp_header.tcp_urg; end
    def tcp_hlen; self.tcp_header.tcp_hlen; end
    def tcp_hlen=(v); self.tcp_header.tcp_hlen= v; end
    def tcp_reserved; self.tcp_header.tcp_reserved; end
    def tcp_reserved=(v); self.tcp_header.tcp_reserved= v; end
    def tcp_ecn; self.tcp_header.tcp_ecn; end
    def tcp_ecn=(v); self.tcp_header.tcp_ecn= v; end
    def tcp_opts; self.tcp_header.tcp_opts; end
    def tcp_opts=(v); self.tcp_header.tcp_opts= v; end
    def tcp_calc_seq; self.tcp_header.tcp_calc_seq; end
    def tcp_calc_src; self.tcp_header.tcp_calc_src; end
    def tcp_opts_len; self.tcp_header.tcp_opts_len; end
    def tcp_calc_hlen; self.tcp_header.tcp_calc_hlen; end
    def tcp_options; self.tcp_header.tcp_options; end
    def tcp_flags_dotmap; self.tcp_header.tcp_flags_dotmap; end
    def tcp_options=(v); self.tcp_header.tcp_options= v; end
    def tcp_sport; self.tcp_header.tcp_sport; end
    def tcp_sport=(v); self.tcp_header.tcp_sport= v; end
    def tcp_dport; self.tcp_header.tcp_dport; end
    def tcp_dport=(v); self.tcp_header.tcp_dport= v; end
    def tcp_recalc(*v); self.tcp_header.tcp_recalc(*v); end
    def tcp_flags_readable; self.tcp_header.tcp_flags_readable; end
    def tcp_ack_readable; self.tcp_header.tcp_ack_readable; end
    def tcp_seq_readable; self.tcp_header.tcp_seq_readable; end
    def tcp_sum_readable; self.tcp_header.tcp_sum_readable; end
    def tcp_opts_readable; self.tcp_header.tcp_opts_readable; end
    def tcp_flags; self.tcp_header.tcp_flags; end
    def tcp_flags=(v); self.tcp_header.tcp_flags= v; end
  end
end
