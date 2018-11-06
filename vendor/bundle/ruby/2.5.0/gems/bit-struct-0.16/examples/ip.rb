require 'bit-struct'

class IP < BitStruct
  unsigned    :ip_v,     4,     "Version"
  unsigned    :ip_hl,    4,     "Header length"
  unsigned    :ip_tos,   8,     "TOS"
  unsigned    :ip_len,  16,     "Length"
  unsigned    :ip_id,   16,     "ID"
  unsigned    :ip_off,  16,     "Frag offset"
  unsigned    :ip_ttl,   8,     "TTL"
  unsigned    :ip_p,     8,     "Protocol"
  unsigned    :ip_sum,  16,     "Checksum"
  octets      :ip_src,  32,     "Source addr"
  octets      :ip_dst,  32,     "Dest addr"
  rest        :body,            "Body of message"

  note "     rest is application defined message body"

  initial_value.ip_v    = 4
  initial_value.ip_hl   = 5
end

if __FILE__ == $0
  ip1 = IP.new
  ip1.ip_tos = 0
  ip1.ip_len = 0
  ip1.ip_id  = 0
  ip1.ip_off = 0
  ip1.ip_ttl = 255
  ip1.ip_p   = 255
  ip1.ip_sum = 0
  ip1.ip_src = "192.168.1.4"
  ip1.ip_dst = "192.168.1.255"
  ip1.body   = "This is the payload text."
  ip1.ip_len = ip1.length

  ip2 = IP.new do |ip|
    ip.ip_tos = 0
    ip.ip_len = 0
    ip.ip_id  = 0
    ip.ip_off = 0
    ip.ip_ttl = 255
    ip.ip_p   = 255
    ip.ip_sum = 0
    ip.ip_src = "192.168.1.4"
    ip.ip_dst = "192.168.1.255"
    ip.body   = "This is the payload text."
    ip.ip_len = ip.length
  end

  ip3 = IP.new(
    :ip_tos => 0,
    :ip_len => 0,
    :ip_id  => 0,
    :ip_off => 0,
    :ip_ttl => 255,
    :ip_p   => 255,
    :ip_sum => 0,
    :ip_src => "192.168.1.4",
    :ip_dst => "192.168.1.255",
    :body   => "This is the payload text."
  ) do |ip|
    ip.ip_len = ip.length
  end

  ip4 = IP.new(ip1) # Construct from a BitStruct (or String)

  raise unless ip1 == ip2
  raise unless ip1 == ip3
  raise unless ip1 == ip4

  ip = ip1

  puts ip.inspect
  puts "-"*50
  puts ip.inspect_detailed
  puts "-"*50
  puts
  puts "Description of IP Packet:"
  puts IP.describe
end
