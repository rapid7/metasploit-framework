require 'ipaddr'

# Validates that value is an IPv4 or IPv6 address.
class IpFormatValidator < ActiveModel::EachValidator
  # Validates that `value` is an IPv4 or IPv4 address.  Ranges in CIDR or netmask notation are not allowed.
  #
  # @param record [#errors, ActiveRecord::Base] ActiveModel or ActiveRecord
  # @param attribute [Symbol] name of IP address attribute.
  # @param value [String, nil] IP address.
  # @return [void]
  # @see IPAddr#ipv4?
  # @see IPAddr#ipv6?
  def validate_each(record, attribute, value)
    begin
      potential_ip = IPAddr.new(value)
    rescue ArgumentError
      record.errors[attribute] << 'must be a valid IPv4 or IPv6 address'
    else
      # if it includes a netmask, then it's not an IP address, but an IP range.
      if potential_ip.ipv4?
        if potential_ip.instance_variable_get(:@mask_addr) != IPAddr::IN4MASK
          record.errors[attribute] << 'must be a valid IPv4 or IPv6 address and not an IPv4 address range in CIDR or netmask notation'
        end
      elsif potential_ip.ipv6?
        if potential_ip.instance_variable_get(:@mask_addr) != IPAddr::IN6MASK
          record.errors[attribute] << 'must be a valid IPv4 or IPv6 address and not an IPv6 address range in CIDR or netmask notation'
        end
      end
    end
  end
end
