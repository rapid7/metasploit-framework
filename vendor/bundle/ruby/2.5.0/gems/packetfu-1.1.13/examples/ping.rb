# Usage:
# rvmsudo ruby examples/ping.rb 8.8.8.8

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)

require 'packetfu'

ip = ARGV[0].chomp

config = PacketFu::Utils.whoami?()

icmp_packet = PacketFu::ICMPPacket.new(:config => config)
icmp_packet.ip_daddr = ip
icmp_packet.payload = "I'm sending ICMP packets using PacketFu!!!"
icmp_packet.icmp_type = 8
icmp_packet.recalc

capture_thread = Thread.new do
  begin
    Timeout::timeout(3) {
      cap = PacketFu::Capture.new(:iface => config[:iface], :start => true)
      cap.stream.each do |p|
        pkt = PacketFu::Packet.parse p
        next unless pkt.is_icmp?
        if pkt.ip_saddr == ip and pkt.icmp_type == 0
          puts "Got ICMP echo reply from #{ip}"
          break
        end
      end
    }
  rescue Timeout::Error
    puts "ICMP echo request timed out"
  end
end

puts "Sending ICMP echo request to #{ip}"
icmp_packet.to_w

capture_thread.join
