# Usage:
# rvmsudo ruby examples/pcap2pcapng.rb test.pcap test.pcapng

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)

require 'packetfu'

pcap_filename = ARGV[0].chomp
pcapng_filename = ARGV[1].chomp

unless File.exists?(pcap_filename)
  puts "PCAP input file #{pcap_filename} could not be found"
end

if File.exists?(pcapng_filename)
  puts "PCAP-NG output file #{pcap_filename} already exists"
  puts "Do you wish to overwrite the file? (Y/N, Default = N)"
  STDOUT.flush
  response = $stdin.gets.chomp
  unless response == "Y"
    puts "Aborting..."
    exit 0
  end
end

puts "Reading PCAP to packet array from #{File.expand_path(pcap_filename)}"
packet_array = PacketFu::PcapFile.file_to_array(pcap_filename)

puts "Writing packet array to PCAP-NG at #{File.expand_path(pcapng_filename)}"
pcapng_file = PacketFu::PcapNG::File.new()
pcapng_file.array_to_file(:array => packet_array, :file => pcapng_filename)
