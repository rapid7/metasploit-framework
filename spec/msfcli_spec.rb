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
    context ".initialize" do
      it "should give me the correct module name in key :module_name after object initialization" do
        args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
        cli = Msfcli.new(args.split(' '))
        cli.instance_variable_get(:@args)[:module_name].should eq('multi/handler')
      end

      it "should give me the correct mode in key :mode after object initialization" do
        args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
        cli = Msfcli.new(args.split(' '))
        cli.instance_variable_get(:@args)[:mode].should eq('E')
      end

      it "should give me the correct module parameters after object initialization" do
        args = "multi/handler payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
        cli = Msfcli.new(args.split(' '))
        cli.instance_variable_get(:@args)[:params].should eq(['payload=windows/meterpreter/reverse_tcp', 'lhost=127.0.0.1'])
      end

      it "should give me an exploit name without the prefix 'exploit'" do
        args = "exploit/windows/browser/ie_cbutton_uaf payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
        cli = Msfcli.new(args.split(' '))
        cli.instance_variable_get(:@args)[:module_name].should eq("windows/browser/ie_cbutton_uaf")
      end

      it "should give me an exploit name without the prefix 'exploits'" do
        args = "exploits/windows/browser/ie_cbutton_uaf payload=windows/meterpreter/reverse_tcp lhost=127.0.0.1 E"
        cli = Msfcli.new(args.split(' '))
        cli.instance_variable_get(:@args)[:module_name].should eq("windows/browser/ie_cbutton_uaf")
      end

      it "should set mode 's' (summary)" do
        args = "multi/handler payload=windows/meterpreter/reverse_tcp s"
        cli = Msfcli.new(args.split(' '))
        cli.instance_variable_get(:@args)[:mode].should eq('s')
      end

      it "should set mode 'h' (help) as default" do
        args = "multi/handler"
        cli = Msfcli.new(args.split(' '))
        cli.instance_variable_get(:@args)[:mode].should eq('h')
      end
    end

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
      it "should generate a whitelist for linux/x86/shell/reverse_tcp with encoder x86/fnstenv_mov" do
        args = "multi/handler payload=linux/x86/shell/reverse_tcp lhost=127.0.0.1 encoder=x86/fnstenv_mov E"
        cli = Msfcli.new(args.split(' '))
        list = cli.generate_whitelist.map { |e| e.to_s }
        answer = [
          /multi\/handler/,
          /stages\/linux\/x86\/shell/,
          /payloads\/(stagers|stages)\/linux\/x86\/.*(reverse_tcp)\.rb$/,
          /encoders\/x86\/fnstenv_mov/,
          /post\/.+/,
          /encoders\/generic\/*/,
          /nops\/.+/
        ].map { |e| e.to_s }

        list.should eq(answer)
      end

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

    context ".engage_mode" do
      it "should show me the summary of module auxiliary/scanner/http/http_version" do
        args = 'auxiliary/scanner/http/http_version s'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }

        stdout.should =~ /Module: auxiliary\/scanner\/http\/http_version/
      end

      it "should show me the options of module auxiliary/scanner/http/http_version" do
        args = 'auxiliary/scanner/http/http_version O'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }

        stdout.should =~ /The target address range or CIDR identifier/
      end

      it "should me the advanced options of module auxiliary/scanner/http/http_version" do
        args = 'auxiliary/scanner/http/http_version A'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }

        stdout.should =~ /UserAgent/
      end

      it "should show me the IDS options of module auxiliary/scanner/http/http_version" do
        args = 'auxiliary/scanner/http/http_version I'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /Insert fake relative directories into the uri/
      end

      it "should show me the targets available for module windows/browser/ie_cbutton_uaf" do
        args = "windows/browser/ie_cbutton_uaf T"
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /IE 8 on Windows 7/
      end

      it "should show me the payloads available for module windows/browser/ie_cbutton_uaf" do
        args = "windows/browser/ie_cbutton_uaf P"
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /windows\/meterpreter\/reverse_tcp/
      end

      it "should try to run the check function of an exploit" do
        args = "windows/smb/ms08_067_netapi rhost=0.0.0.1 C"  # Some BS IP so we can fail
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /failed/
      end

      it "should warn my auxiliary module isn't supported by mode 'p' (show payloads)" do
        args = 'auxiliary/scanner/http/http_version p'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /This type of module does not support payloads/
      end

      it "should warn my auxiliary module isn't supported by mode 't' (show targets)" do
        args = 'auxiliary/scanner/http/http_version t'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /This type of module does not support targets/
      end

      it "should warn my exploit module isn't supported by mode 'ac' (show actions)" do
        args = 'windows/browser/ie_cbutton_uaf ac'
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /This type of module does not support actions/
      end

      it "should show actions available for module auxiliary/scanner/http/http_put" do
        args = "auxiliary/scanner/http/http_put ac"
        stdout = get_stdout {
          cli = Msfcli.new(args.split(' '))
          m = cli.init_modules
          cli.engage_mode(m)
        }
        stdout.should =~ /DELETE/
      end

    end

  end
end