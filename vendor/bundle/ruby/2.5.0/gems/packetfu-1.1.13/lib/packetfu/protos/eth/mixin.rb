# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the EthHeaders. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'eth_header' method (assuming that it is a EthHeader object)
  module EthHeaderMixin
    def eth_daddr; self.eth_header.eth_daddr ; end
    def eth_daddr=(v); self.eth_header.eth_daddr= v; end
    def eth_dst; self.eth_header.eth_dst ; end
    def eth_dst=(v); self.eth_header.eth_dst= v; end
    def eth_dst_readable; self.eth_header.eth_dst_readable ; end
    def eth_proto; self.eth_header.eth_proto ; end
    def eth_proto=(v); self.eth_header.eth_proto= v; end
    def eth_proto_readable; self.eth_header.eth_proto_readable ; end
    def eth_saddr; self.eth_header.eth_saddr ; end
    def eth_saddr=(v); self.eth_header.eth_saddr= v; end
    def eth_src; self.eth_header.eth_src ; end
    def eth_src=(v); self.eth_header.eth_src= v; end
    def eth_src_readable; self.eth_header.eth_src_readable ; end
  end
end
