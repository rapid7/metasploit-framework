# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the ARPHeaders. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'arp_header' method (assuming that it is a ARPHeader object)
  module ARPHeaderMixin
    def arp_hw=(v); self.arp_header.arp_hw= v; end
    def arp_hw; self.arp_header.arp_hw; end
    def arp_proto=(v); self.arp_header.arp_proto= v; end
    def arp_proto; self.arp_header.arp_proto; end
    def arp_hw_len=(v); self.arp_header.arp_hw_len= v; end
    def arp_hw_len; self.arp_header.arp_hw_len; end
    def arp_proto_len=(v); self.arp_header.arp_proto_len= v; end
    def arp_proto_len; self.arp_header.arp_proto_len; end
    def arp_opcode=(v); self.arp_header.arp_opcode= v; end
    def arp_opcode; self.arp_header.arp_opcode; end
    def arp_src_mac=(v); self.arp_header.arp_src_mac= v; end
    def arp_src_mac; self.arp_header.arp_src_mac; end
    def arp_src_ip=(v); self.arp_header.arp_src_ip= v; end
    def arp_src_ip; self.arp_header.arp_src_ip; end
    def arp_dst_mac=(v); self.arp_header.arp_dst_mac= v; end
    def arp_dst_mac; self.arp_header.arp_dst_mac; end
    def arp_dst_ip=(v); self.arp_header.arp_dst_ip= v; end
    def arp_dst_ip; self.arp_header.arp_dst_ip; end
    def arp_saddr_mac=(v); self.arp_header.arp_saddr_mac= v; end
    def arp_saddr_mac; self.arp_header.arp_saddr_mac; end
    def arp_daddr_mac=(v); self.arp_header.arp_daddr_mac= v; end
    def arp_daddr_mac; self.arp_header.arp_daddr_mac; end
    def arp_saddr_ip=(v); self.arp_header.arp_saddr_ip= v; end
    def arp_saddr_ip; self.arp_header.arp_saddr_ip; end
    def arp_daddr_ip=(v); self.arp_header.arp_daddr_ip= v; end
    def arp_daddr_ip; self.arp_header.arp_daddr_ip; end
    def arp_src_mac_readable; self.arp_header.arp_src_mac_readable; end
    def arp_dst_mac_readable; self.arp_header.arp_dst_mac_readable; end
    def arp_src_ip_readable; self.arp_header.arp_src_ip_readable; end
    def arp_dst_ip_readable; self.arp_header.arp_dst_ip_readable; end
    def arp_proto_readable; self.arp_header.arp_proto_readable; end
  end
end
