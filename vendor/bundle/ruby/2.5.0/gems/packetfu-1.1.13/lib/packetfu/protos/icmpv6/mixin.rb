module PacketFu
  # This Mixin simplifies access to the ICMPv6Headers. Mix this in with your 
  # packet interface, and it will add methods that essentially delegate to
  # the 'icmpv6_header' method (assuming that it is a ICMPv6Header object)
  module ICMPv6HeaderMixin
    def icmpv6_type=(v); self.icmpv6_header.icmpv6_type= v; end
    def icmpv6_type; self.icmpv6_header.icmpv6_type; end
    def icmpv6_code=(v); self.icmpv6_header.icmpv6_code= v; end
    def icmpv6_code; self.icmpv6_header.icmpv6_code; end
    def icmpv6_sum=(v); self.icmpv6_header.icmpv6_sum= v; end
    def icmpv6_sum; self.icmpv6_header.icmpv6_sum; end
    def icmpv6_sum_readable; self.icmpv6_header.icmpv6_sum_readable; end
  end
end
