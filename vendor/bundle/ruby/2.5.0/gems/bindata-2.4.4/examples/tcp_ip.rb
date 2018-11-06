require 'bindata'

# This is a simple protocol analyser for examining IPv4 packets
# captured with libpcap on an ethernet network.
#
# The dump file can be obtained like this:
#
#     sudo tcpdump -i eth0 -s 0 -n -w dump.pcap
#


# Present MAC addresses in a human readable way
class MacAddr < BinData::Primitive
  array :octets, type: :uint8, initial_length: 6

  def set(val)
    self.octets = val.split(/\./).collect(&:to_i)
  end

  def get
    self.octets.collect { |octet| "%02x" % octet }.join(":")
  end
end

# Present IP addresses in a human readable way
class IPAddr < BinData::Primitive
  array :octets, type: :uint8, initial_length: 4

  def set(val)
    self.octets = val.split(/\./).collect(&:to_i)
  end

  def get
    self.octets.collect { |octet| "%d" % octet }.join(".")
  end
end

# TCP Protocol Data Unit
class TCP_PDU < BinData::Record
  endian :big

  uint16 :src_port
  uint16 :dst_port
  uint32 :seq
  uint32 :ack_seq
  bit4   :doff
  bit4   :res1
  bit2   :res2
  bit1   :urg
  bit1   :ack
  bit1   :psh
  bit1   :rst
  bit1   :syn
  bit1   :fin
  uint16 :window
  uint16 :checksum
  uint16 :urg_ptr
  string :options, read_length: :options_length_in_bytes
  rest   :payload

  def options_length_in_bytes
    (doff - 5 ) * 4
  end
end

# UDP Protocol Data Unit
class UDP_PDU < BinData::Record
  endian :big

  uint16 :src_port
  uint16 :dst_port
  uint16 :len
  uint16 :checksum
  rest   :payload
end

# IP Protocol Data Unit
class IP_PDU < BinData::Record
  endian :big

  bit4   :version, asserted_value: 4
  bit4   :header_length
  uint8  :tos
  uint16 :total_length
  uint16 :ident
  bit3   :flags
  bit13  :frag_offset
  uint8  :ttl
  uint8  :protocol
  uint16 :checksum
  ip_addr :src_addr
  ip_addr :dest_addr
  string :options, read_length: :options_length_in_bytes
  buffer :payload, length: :payload_length_in_bytes do
    choice :payload, selection: :protocol do
      tcp_pdu  6
      udp_pdu 17
      rest    :default
    end
  end

  def header_length_in_bytes
    header_length * 4
  end

  def options_length_in_bytes
    header_length_in_bytes - options.rel_offset
  end

  def payload_length_in_bytes
    total_length - header_length_in_bytes
  end
end

# Ethernet Frame - NOTE only ipv4 is supported
class Ether < BinData::Record
  IPV4 = 0x0800

  endian :big
  mac_addr :dst
  mac_addr :src
  uint16   :ether_type
  choice   :payload, selection: :ether_type do
    ip_pdu IPV4
    rest   :default
  end
end

class Pcap
  def initialize(filename)
    @filename = filename
  end

  def each_record
    File.open(@filename) do |io|
      file = PcapFile.read(io)
      file.records.each do |rec|
        yield rec.data
      end
    end
  end

  class PcapFile < BinData::Record
    endian :little

    struct :head do
      uint32 :magic
      uint16 :major
      uint16 :minor
      int32  :this_zone
      uint32 :sig_figs
      uint32 :snaplen
      uint32 :linktype
    end

    array :records, read_until: :eof do
      uint32 :ts_sec
      uint32 :ts_usec
      uint32 :incl_len
      uint32 :orig_len
      string :data, length: :incl_len
    end
  end
end

require 'pp'
unless File.exist?('dump.pcap')
  puts "No dump file found. Create one with: sudo tcpdump -i eth0 -s 0 -n -w dump.pcap"
  exit 1
end

cap = Pcap.new('dump.pcap')
cap.each_record do |str|
  pp Ether.read(str)
end
