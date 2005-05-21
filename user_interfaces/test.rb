#!/usr/bin/ruby -I../Framework -I../Modules

require 'Msf/Framework'
require 'Encoders/IA32/JmpCallAdditive'
require 'Nops/IA32/SingleByte'

framework = Msf::Framework.new

framework.add_log_sink(Msf::Logging::Sinks::Flatfile.new('/tmp/msfcli.log'))

#encoder = framework.encoders.instantiate('gen_ia32_jmp_call_additive')
encoder = Msf::Encoders::Generic::IA32::JmpCallAdditive.new

puts "#{encoder.author_to_s}"
puts "#{encoder.arch_to_s}"

puts "#{encoder.arch?('ia32')} #{encoder.arch?('jabba')}"

begin
	encoded = encoder.encode("\xcc\x90\x90\x90ABCDEFGHIJKLMNOPQRSTUVWXYZ", "\x87")
rescue Msf::Encoding::BadcharException => detail
	puts "bad char at #{detail.index} #{detail.buf.unpack('H*')[0]}"

	exit
end

puts encoded.unpack("H*")[0]

nop = Msf::Nops::IA32::SingleByte.new

sled = nop.generate_sled(
	100,
	'Random'        => true)
#	'Badchars'      => "\x95")
#	'SaveRegisters' => [ 'eax' ])

puts sled.unpack("H*")[0]
