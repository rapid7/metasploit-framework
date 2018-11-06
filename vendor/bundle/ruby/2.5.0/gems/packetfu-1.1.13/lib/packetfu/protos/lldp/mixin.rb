# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the LLDPHeaders. Mix this in with your
  # packet interface, and it will add methods that essentially delegate to
  # the 'lldp_header' method (assuming that it is a LLDPHeader object)
  module LLDPHeaderMixin
    def lldp_chassis_id_type=(v); self.lldp_header.lldp_chassis_id_type= v; end
    def lldp_chassis_id_type; self.lldp_header.lldp_chassis_id_type; end
    def lldp_chassis_id=(v); self.lldp_header.lldp_chassis_id= v; end
    def lldp_chassis_id; self.lldp_header.lldp_chassis_id_readable(); end

    def lldp_port_id_type=(v); self.lldp_header.lldp_port_id_type= v; end
    def lldp_port_id_type; self.lldp_header.lldp_port_id_type; end
    def lldp_port_id=(v); self.lldp_header.lldp_port_id= v; end
    def lldp_port_id; self.lldp_header.lldp_port_id_readable(); end

    def lldp_ttl=(v); self.lldp_header.lldp_ttl= v; end
    def lldp_ttl; self.lldp_header.lldp_ttl; end

    def lldp_port_description=(v); self.lldp_header.lldp_port_description= v; end
    def lldp_port_description; self.lldp_header.lldp_port_description; end

    def lldp_system_name=(v); self.lldp_header.lldp_system_name= v; end
    def lldp_system_name; self.lldp_header.lldp_system_name; end

    def lldp_system_description=(v); self.lldp_header.lldp_system_description= v; end
    def lldp_system_description; self.lldp_header.lldp_system_description; end

    def lldp_capabilty=(v); self.lldp_header.lldp_capabilty= v; end
    def lldp_capabilty; self.lldp_header.lldp_capabilty_readable(); end

    def lldp_enabled_capability=(v); self.lldp_header.lldp_enabled_capability= v; end
    def lldp_enabled_capability; self.lldp_header.lldp_enabled_capability_readable(); end

    def lldp_address_type=(v); self.lldp_header.lldp_address_type= v; end
    def lldp_address_type; self.lldp_header.lldp_address_type; end

    def lldp_address=(v); self.lldp_header.lldp_saddr_ip= v; end
    def lldp_address; self.lldp_header.lldp_saddr_ip(); end

    def lldp_interface_type=(v); self.lldp_header.lldp_interface_type= v; end
    def lldp_interface_type; self.lldp_header.lldp_interface_type; end

    def lldp_interface=(v); self.lldp_header.lldp_interface= v; end
    def lldp_interface; self.lldp_header.lldp_interface; end

    def lldp_oid=(v); self.lldp_header.lldp_oid= v; end
    def lldp_oid; self.lldp_header.lldp_oid; end

    def lldp_saddr_mac=(v); self.lldp_header.lldp_saddr_mac= v; end
    def lldp_saddr_mac; self.lldp_header.lldp_saddr_mac; end
    def lldp_saddr_ip=(v); self.lldp_header.lldp_saddr_ip= v; end
    def lldp_saddr_ip; self.lldp_header.lldp_saddr_ip(); end

  end
end
