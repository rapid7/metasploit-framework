#!/usr/bin/ruby -I../Lib -I../Modules

require 'msf/core'
#require 'encoders/ia32/jmp_call_additive'
#require 'nops/ia32/single_byte'

register_log_source('core', Msf::Logging::Sinks::Flatfile.new('/tmp/msfcli.log'))

dlog('yo yo yo')

framework = Msf::Framework.new

framework.modules.add_module_path('/home/mmiller/msf/rubyhacks/prototype/Modules')


framework.encoders.each_module { |mod|
	puts "default: got encoder #{mod}"
}

framework.encoders.each_module(
		'arch' => Msf::ARCH_X86) { |mod|
	puts "arch filter: got encoder #{mod}"
}

encoder = framework.encoders.create('JmpCallAdditive')

#encoder = framework.encoders.instantiate('gen_ia32_jmp_call_additive')

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
#	'BadChars'      => "\x95")
#	'SaveRegisters' => [ 'eax' ])

puts sled.unpack("H*")[0]
