require 'spec_helper'

load Metasploit::Framework.root.join('msfcli').to_path

require 'fastlib'
require 'msfenv'
require 'msf/ui'
require 'msf/base'


describe Msfcli do

	# Get stdout:
	# http://stackoverflow.com/questions/11349270/test-output-to-command-line-with-rspec
	def get_stdout(&block)
		out = $stdout
		$stdout = fake = StringIO.new
		begin
			yield
		ensure
			$stdout = out
		end
		fake.string
	end

	context "Class methods" do

		context ".usage" do
			it "should see a help menu" do
				out = get_stdout {
					cli = Msfcli.new([])
					cli.usage	
				}
				out.should =~ /Usage/
			end
		end

		#
		# This one is slow because we're loading all modules
		#
		context ".dump_module_list" do
			it "it should dump a list of modules" do
				tbl = ''
				stdout = get_stdout {
					cli = Msfcli.new([])
					tbl = cli.dump_module_list
				}
				tbl.should =~ /Exploits/ and stdout.should =~ /Please wait/
			end
		end

		context ".guess_payload_name" do
			cli = Msfcli.new([])

			it "should contain matches nedded for windows/meterpreter/reverse_tcp" do
				m = cli.guess_payload_name('windows/meterpreter/reverse_tcp')
				m.should eq([/stages\/windows\/meterpreter/, /payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/])
			end

			it "should contain matches needed for windows/shell/reverse_tcp" do
				m = cli.guess_payload_name('windows/shell/reverse_tcp')
				m.should eq([/stages\/windows\/shell/, /payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/])
			end

			it "should contain matches needed for windows/shell_reverse_tcp" do
				m = cli.guess_payload_name('windows/shell_reverse_tcp')
				m.should eq([/stages\/windows\/shell/, /payloads\/(singles|stagers|stages)\/windows\/.*(shell_reverse_tcp)\.rb$/])
			end

			it "should contain matches needed for php/meterpreter_reverse_tcp" do
				m = cli.guess_payload_name('php/meterpreter_reverse_tcp')
				m.should eq([/stages\/php\/meterpreter/, /payloads\/(stagers|stages)\/php\/.*(meterpreter_reverse_tcp)\.rb$/])
			end

			it "should contain matches needed for linux/x86/meterpreter/reverse_tcp" do
				m = cli.guess_payload_name('linux/x86/meterpreter/reverse_tcp')
				m.should eq([/stages\/linux\/x86\/meterpreter/, /payloads\/(stagers|stages)\/linux\/x86\/.*(reverse_tcp)\.rb$/])
			end

			it "should contain matches needed for java/meterpreter/reverse_tcp" do
				m = cli.guess_payload_name('java/meterpreter/reverse_tcp')
				m.should eq([/stages\/java\/meterpreter/, /payloads\/(stagers|stages)\/java\/.*(reverse_tcp)\.rb$/])
			end

			it "should contain matches needed for cmd/unix/reverse" do
				m = cli.guess_payload_name('cmd/unix/reverse')
				m.should eq([/stages\/cmd\/shell/, /payloads\/(singles|stagers|stages)\/cmd\/.*(reverse)\.rb$/])
			end

			it "should contain matches needed for bsd/x86/shell_reverse_tcp" do
				m = cli.guess_payload_name('bsd/x86/shell_reverse_tcp')
				m.should eq([/stages\/bsd\/x86\/shell/, /payloads\/(singles|stagers|stages)\/bsd\/x86\/.*(shell_reverse_tcp)\.rb$/])
			end
		end

		context ".guess_encoder_name" do
			cli = Msfcli.new([])
			it "should contain a match for x86/shikata_ga_nai" do
				encoder = 'x86/shikata_ga_nai'
				m = cli.guess_encoder_name(encoder)
				m.should eq([/encoders\/#{encoder}/])
			end
		end

		context ".guess_nop_name" do
			cli = Msfcli.new([])
			it "should contain a match for guess_nop_name" do
				nop = 'x86/single_byte'
				m = cli.guess_nop_name(nop)
				m.should eq([/nops\/#{nop}/])
			end
		end

		context ".generate_whitelist" do
			it "should generate a whitelist for windows/meterpreter/reverse_tcp with default options" do
				args = 'multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E'
				cli = Msfcli.new(args.split(' '))
				list = cli.generate_whitelist.map { |e| e.to_s }
				answer = [
					/multi\/handler/,
					/stages\/windows\/meterpreter/,
					/payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/,
					/post\/.+/,
					/encoders\/generic\/*/,
					/encoders\/.+/,
					/nops\/.+/
				].map { |e| e.to_s }

				list.should eq(answer)
			end

			it "should generate a whitelist for windows/meterpreter/reverse_tcp with options: encoder='' post='' nop=''" do
				args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 encoder='' post='' nop='' E"
				cli = Msfcli.new(args.split(' '))
				list = cli.generate_whitelist.map { |e| e.to_s }
				answer = [
					/multi\/handler/,
					/stages\/windows\/meterpreter/,
					/payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/,
					/encoders\/''/,
					/post\/''/,
					/nops\/''/,
					/encoders\/generic\/*/
				].map { |e| e.to_s }

				list.should eq(answer)
			end

			it "should generate a whitelist for windows/meterpreter/reverse_tcp with options: encoder= post= nop=" do
				args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 encoder= post= nop= E"
				cli = Msfcli.new(args.split(' '))
				list = cli.generate_whitelist.map { |e| e.to_s }
				answer = [
					/multi\/handler/,
					/stages\/windows\/meterpreter/,
					/payloads\/(stagers|stages)\/windows\/.*(reverse_tcp)\.rb$/,
					/encoders\/generic\/*/
				].map { |e| e.to_s }

				list.should eq(answer)
			end
		end

		context ".init_modules" do
			it "should have multi/handler module initialized" do
				args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
				m    = ''
				stdout = get_stdout {
					cli = Msfcli.new(args.split(' '))
					m = cli.init_modules
				}

				m[:module].class.to_s.should =~ /^Msf::Modules::/
			end

			it "should have my payload windows/meterpreter/reverse_tcp initialized" do
				args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
				m    = ''
				stdout = get_stdout {
					cli = Msfcli.new(args.split(' '))
					m = cli.init_modules
				}

				m[:payload].class.to_s.should =~ /<Class:/
			end

			it "should have my modules initialized with the correct parameters" do
				args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
				m    = ''
				stdout = get_stdout {
					cli = Msfcli.new(args.split(' '))
					m = cli.init_modules
				}

				m[:module].datastore['lhost'].should eq("127.0.0.1")
			end

			it "should give me an empty hash as a result of an invalid module name" do
				args = "WHATEVER payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
				m    = ''
				stdout = get_stdout {
					cli = Msfcli.new(args.split(' '))
					m = cli.init_modules
				}

				m.should eq({})
			end
		end

	end
end