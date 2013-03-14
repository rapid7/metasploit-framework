# encoding: utf-8
require 'mail/fields/common/address_container'

module Mail
  module CommonAddress # :nodoc:
      
    def parse(val = value)
      unless val.blank?
        @tree = AddressList.new(encode_if_needed(val))
      else
        nil
      end
    end
    
    def charset
      @charset
    end
    
    def encode_if_needed(val)
      Encodings.address_encode(val, charset)
    end
    
    # Allows you to iterate through each address object in the syntax tree
    def each
      tree.addresses.each do |address|
        yield(address)
      end
    end

    # Returns the address string of all the addresses in the address list
    def addresses
      list = tree.addresses.map { |a| a.address }
      Mail::AddressContainer.new(self, list)
    end

    # Returns the formatted string of all the addresses in the address list
    def formatted
      list = tree.addresses.map { |a| a.format }
      Mail::AddressContainer.new(self, list)
    end
  
    # Returns the display name of all the addresses in the address list
    def display_names
      list = tree.addresses.map { |a| a.display_name }
      Mail::AddressContainer.new(self, list)
    end
  
    # Returns the actual address objects in the address list
    def addrs
      list = tree.addresses
      Mail::AddressContainer.new(self, list)
    end
  
    # Returns a hash of group name => address strings for the address list
    def groups
      @groups = Hash.new
      tree.group_recipients.each do |group|
        @groups[group.group_name.text_value.to_str] = get_group_addresses(group.group_list)
      end
      @groups
    end
  
    # Returns the addresses that are part of groups
    def group_addresses
      groups.map { |k,v| v.map { |a| a.format } }.flatten
    end

    # Returns the name of all the groups in a string
    def group_names # :nodoc:
      tree.group_names
    end
  
    def default
      addresses
    end

    def <<(val)
      case
      when val.nil?
        raise ArgumentError, "Need to pass an address to <<"
      when val.blank?
        parse(encoded)
      else
        parse((formatted + [val]).join(", "))
      end
    end
  
    private
  
    def do_encode(field_name)
      return '' if value.blank?
      address_array = tree.addresses.reject { |a| group_addresses.include?(a.encoded) }.compact.map { |a| a.encoded }
      address_text  = address_array.join(", \r\n\s")
      group_array = groups.map { |k,v| "#{k}: #{v.map { |a| a.encoded }.join(", \r\n\s")};" }
      group_text  = group_array.join(" \r\n\s")
      return_array = [address_text, group_text].reject { |a| a.blank? }
      "#{field_name}: #{return_array.join(", \r\n\s")}\r\n"
    end

    def do_decode
      return nil if value.blank?
      address_array = tree.addresses.reject { |a| group_addresses.include?(a.decoded) }.map { |a| a.decoded }
      address_text  = address_array.join(", ")
      group_array = groups.map { |k,v| "#{k}: #{v.map { |a| a.decoded }.join(", ")};" }
      group_text  = group_array.join(" ")
      return_array = [address_text, group_text].reject { |a| a.blank? }
      return_array.join(", ")
    end

    # Returns the syntax tree of the Addresses
    def tree # :nodoc:
      @tree ||= AddressList.new(value)
    end
  
    def get_group_addresses(group_list)
      if group_list.respond_to?(:addresses)
        group_list.addresses.map do |address_tree|
          Mail::Address.new(address_tree)
        end
      else
        []
      end
    end
  end
end
