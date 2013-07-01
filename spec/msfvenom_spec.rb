
require 'spec_helper'
require 'msf/core'
# doesn't end in .rb or .so, so have to load instead of require
load File.join(Msf::Config.install_root, 'msfvenom')

describe MsfVenom do
	subject(:venom) { described_class.new }

	describe "#dump_encoders" do
		it "should list known encoders" do
			dump = venom.dump_encoders

			%w|
				generic/none
				x86/shikata_ga_nai
				x64/xor
				php/base64
			|.each do |name|
				dump.should include(name)
			end
		end
	end


	describe "#dump_payloads" do
		it "should list known payloads" do
			dump = venom.dump_payloads

			%w|
				windows/meterpreter/reverse_tcp
				windows/meterpreter/reverse_https
				linux/x86/shell/reverse_tcp
				linux/x86/shell_reverse_tcp
				linux/x64/shell/reverse_tcp
				linux/x64/shell_reverse_tcp
				linux/armle/shell/reverse_tcp
				linux/armle/shell_reverse_tcp
				linux/mipsbe/shell_reverse_tcp
				java/meterpreter/reverse_tcp
				java/meterpreter/reverse_https
				php/meterpreter/reverse_tcp
			|.each do |name|
				dump.should include(name)
			end
		end
	end

end
