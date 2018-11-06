# -*- coding: binary -*-
module PacketFu
  # LLDPHeader is a complete LLDP struct, used in LLDPPacket.

  class LLDPHeader < Struct.new(:lldp_chassis_id_type, :lldp_chassis_id, :lldp_port_id_type, :lldp_port_id, :lldp_ttl, :lldp_port_description, :lldp_system_name, :lldp_system_description, :lldp_capabilty, :lldp_enabled_capability, :lldp_address_type, :lldp_address, :lldp_interface_type, :lldp_interface, :lldp_oid)
    include StructFu

    def initialize(args={})
      src_mac = (args[:lldp_port_id] if :lldp_port_id_type == 3) || (args[:config][:eth_src] if args[:config])
      src_ip_bin = (args[:lldp_address] if :lldp_address_type == 1) || (args[:config][:ip_src_bin] if args[:config])

      super(Int8.new(args[:lldp_chassis_id_type] || 4),
      StructFu::String.new.read(:lldp_chassis_id),
      Int8.new(args[:lldp_port_id_type] || 3),
      EthMac.new.read(src_mac),
      Int16.new(args[:lldp_ttl] || 120),
      StructFu::String.new.read(:lldp_port_description) || "",
      StructFu::String.new.read(:lldp_system_name) || "",
      StructFu::String.new.read(:lldp_system_description) || "",
      Int16.new(args[:lldp_capabilty] || 0x0080),
      Int16.new(args[:lldp_enabled_capability] || 0x0080),
      Int8.new(args[:lldp_address_type] || 1),
      StructFu::String.new.read(:lldp_address) || src_ip_bin,
      Int8.new(args[:lldp_interface_type] || 2),
      Int32.new(args[:lldp_interface]),
      StructFu::String.new.read(:lldp_oid) || ""
      )
    end

    # Returns the object in string form.
    def to_s
      self.to_a.map {|x| x.to_s}.join
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      index = 0
      #check for lldp pdu end
      while (str[index,2] != "\x00\x00") && (index+2 < str.size)
        tlv_known = false
        #chassis subtype
        if str[index,1] == "\x02"
          tlv_known = true
          tlv_length = str[index+1,1].unpack("U*").join.to_i
          self[:lldp_chassis_id_type].read(str[index+2,1])
          self[:lldp_chassis_id].read(str[index+3, tlv_length - 1])
          index += tlv_length + 2
        end
        #port subtype
        if str[index,1] == "\x04"
          tlv_known = true
          tlv_length = str[index+1,1].unpack("U*").join.to_i
          self[:lldp_port_id_type].read(str[index+2,1])
          self[:lldp_port_id].read(str[index+3, tlv_length - 1])
          index += tlv_length + 2
        end
        #ttl subtype
        if str[index,1] == "\x06"
          tlv_known = true
          tlv_length = str[index+1,1].unpack("U*").join.to_i
          self[:lldp_ttl].read(str[index+2, tlv_length])
          index += tlv_length + 2
        end
        #port description
        if str[index,1] == "\x08"
          tlv_known = true
          tlv_length = str[index+1,1].unpack("U*").join.to_i
          self[:lldp_port_description].read(str[index+2, tlv_length])
          index += tlv_length + 2
        end
        #system name
        if str[index,1] == "\x0a"
          tlv_known = true
          tlv_length = str[index+1,1].unpack("U*").join.to_i
          self[:lldp_system_name].read(str[index+2, tlv_length])
          index += tlv_length + 2
        end
        #system description
        if str[index,1] == "\x0c"
          tlv_known = true
          tlv_length = str[index+1,1].unpack("U*").join.to_i
          self[:lldp_system_description].read(str[index+2, tlv_length])
          index += tlv_length + 2
        end
        #system capabilities
        if str[index,1] == "\x0e"
          tlv_known = true
          tlv_length = str[index+1,1].unpack("U*").join.to_i
          self[:lldp_capabilty].read(str[index+2, 2])
          self[:lldp_enabled_capability].read(str[index+4, 2])
          index += tlv_length + 2
        end
        #management address
        if str[index,1] == "\x10"
          tlv_known = true
          tlv_length = str[index + 1,1].unpack("U*").join.to_i
          addr_length = str[index + 2, 1].unpack("U*").join.to_i
          self[:lldp_address_type].read(str[index + 3, 1])
          self[:lldp_address].read(str[index + 4,addr_length - 1])
          self[:lldp_interface_type].read(str[index + addr_length + 3, 1].unpack("U*").join.to_i)
          self[:lldp_interface].read(str[index + addr_length + 4, 4])
          oid_string_length = str[index + addr_length + 8, 1].unpack("U*").join.to_i
          if oid_string_length > 0
            self[:lldp_oid].read(str[index + addr_length + 9, oid_string_length])
          end
          index += tlv_length + 2
        end

        #if tlv type is unknown jump over it
        unless tlv_known
          tlv_length = str[index+1,1].unpack("U*").join.to_i
          index += tlv_length + 2
        end
      end
      self
    end

    # Setter for the LLDP chassis id type.
    def lldp_chassis_id_type=(i); typecast i; end
    # Getter for the LLDP chassis id type.
    def lldp_chassis_id_type; self[:lldp_chassis_id_type].to_i; end
    # Setter for the LLDP chassis id.
    def lldp_chassis_id=(i); typecast i; end
    # Getter for the LLDP chassis id .
    def lldp_chassis_id_readable()
      if self[:lldp_chassis_id_type].to_i == 4
        return EthHeader.str2mac(self[:lldp_chassis_id].to_s)
      else
        return self[:lldp_chassis_id].to_s
      end
    end
    # Setter for the LLDP port id type.
    def lldp_port_id_type=(i); typecast i; end
    # Getter for the LLDP port id type.
    def lldp_port_id_type; self[:lldp_port_id_type].to_i; end
    # Setter for the LLDP port id .
    def lldp_port_id=(i); typecast i; end
    # Getter for the LLDP port id.
    def lldp_port_id_readable()
      #if mac addr
      if self[:lldp_port_id_type].to_i == 3
        return EthHeader.str2mac(self[:lldp_port_id].to_s)
      else
        return self[:lldp_port_id].to_s
      end
    end

    # Set the source MAC address in a more readable way.
    def lldp_saddr_mac=(mac)
      mac = EthHeader.mac2str(mac)
      self[:lldp_port_id_type] = 3
      self[:lldp_port_id].read(mac)
      self.lldp_port_id
    end

    # Setter for the LLDP ttl.
    def lldp_ttl=(i); typecast i; end
    # Getter for the LLDP ttl.
    def lldp_ttl; self[:lldp_ttl].to_i; end
    # Setter for the LLDP port description.
    def lldp_port_description=(i); typecast i; end
    # Getter for the LLDP port description.
    def lldp_port_description; self[:lldp_port_description].to_s; end
    # Setter for the LLDP system name.
    def lldp_system_name=(i); typecast i; end
    # Getter for the LLDP system name.
    def lldp_system_name; self[:lldp_system_name].to_s; end
    # Setter for the LLDP system description.
    def lldp_system_description=(i); typecast i; end
    # Getter for the LLDP system description.
    def lldp_system_description; self[:lldp_system_description].to_s; end
    # Setter for the LLDP capability.
    def lldp_capabilty=(i); typecast i; end
    # Setter for the LLDP enabled capability.
    def lldp_enabled_capability=(i); typecast i; end

    # Setter for the LLDP address type.
    def lldp_address_type=(i); typecast i; end
    # Getter for the LLDP address type.
    def lldp_address_type; self[:lldp_address_type].to_i; end
    # Setter for the LLDP interface type.
    def lldp_interface_type=(i); typecast i; end
    # Getter for the LLDP interface type.
    def lldp_interface_type; self[:lldp_interface_type].to_i; end
    # Setter for the LLDP interface.
    def lldp_interface=(i); typecast i; end
    # Getter for the LLDP interface type.
    def lldp_interface; self[:lldp_interface].to_i; end
    # Setter for the LLDP oid.
    def lldp_oid=(i); typecast i; end
    # Getter for the LLDP oid type.
    def lldp_oid; self[:lldp_oid].to_i; end


    # Get a more readable source MAC address.
    def lldp_saddr_mac
      EthHeader.str2mac(self[:lldp_port_id].to_s)
    end

    # Set a more readable source IP address.
    def lldp_saddr_ip=(addr)
      self[:lldp_address_type] = 1
      self[:lldp_address].read_quad(addr)
    end

    # Get a more readable source IP address.
    def lldp_saddr_ip
      #ipv4 or ipv6
      if (self[:lldp_address_type].to_i == 1) or (self[:lldp_address_type].to_i == 2)
        begin
          IPAddr::ntop(self[:lldp_address])
        rescue
          self[:lldp_address]
        end
      elsif  self[:lldp_address_type].to_i == 6
        #mac
        EthHeader.str2mac(self[:lldp_address].to_s)
      end
    end

    def lldp_address_type_readable
      case lldp_address_type
      when 1
        "IPv4"
      when 2
        "IPv6"
      when 6
        "MAC"
      else
        lldp_address_type
      end
    end

    def lldp_capabilty_readable
      "0x%04x" % lldp_capabilty
    end

    def lldp_enabled_capability_readable
      "0x%04x" % lldp_enabled_capability
    end


    # Readability aliases

    alias :lldp_chassis_id :lldp_saddr_mac
    alias :lldp_address :lldp_saddr_ip

  end # class LLDPHeader
end
