require "ipaddr"

class IpFormatValidator < ActiveModel::EachValidator
  def validate_each(object, attribute, value)
    error_message_block = lambda{ object.errors[attribute] << " must be a valid IPv4 or IPv6 address" }
    begin
      potential_ip = IPAddr.new(value)
      error_message_block.call unless potential_ip.ipv4? || potential_ip.ipv6?
    rescue ArgumentError
      error_message_block.call
    end
  end
end
