
require 'spec_helper'
require 'msf/core'
# doesn't end in .rb or .so, so have to load instead of require
load File.join(Msf::Config.install_root, 'msfvenom')

shared_examples_for "nop dumper" do
  it "should list known nops" do
    %w!
      x86/opty2
      armle/simple
    !.each do |name|
      dump.should include(name)
    end
  end
end

shared_examples_for "encoder dumper" do
  it "should list known encoders" do
    %w!
      generic/none
      x86/shikata_ga_nai
      x64/xor
    !.each do |name|
      dump.should include(name)
    end
  end
end

shared_examples_for "payload dumper" do
  it "should list known payloads" do
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
    it_behaves_like "encoder dumper" do
      let(:dump) { venom.dump_encoders }
    end
  end

  describe "#dump_nops" do
    it_behaves_like "nop dumper" do
      let(:dump) { venom.dump_nops }
    end
  end

  describe "#dump_payloads" do
    it_behaves_like "payload dumper" do
      let(:dump) { venom.dump_payloads }
    end
  end

  describe "#parse_args" do

    context "help" do
      it "should raise UsageError" do
        expect { venom.parse_args(%w! -h !) }.to raise_error(MsfVenom::UsageError)
        expect { venom.parse_args(%w! --help !) }.to raise_error(MsfVenom::UsageError)
        expect { venom.parse_args(%w! --help-formats !) }.to raise_error(MsfVenom::UsageError)
      end
    end

    context "with bad arguments" do

      it "should raise UsageError with empty arguments" do
        expect { venom.parse_args([]) }.to raise_error(MsfVenom::UsageError)
      end

      it "should raise with unexpected options" do
        expect { venom.parse_args(%w! --non-existent-option !) }.to raise_error(MsfVenom::UsageError)
      end

      %w! --platform -a -b -c -f -p -n -s -i -x !.each do |required_arg|
        it "should raise UsageError with no arg for option #{required_arg}" do
          expect { venom.parse_args([required_arg]) }.to raise_error(MsfVenom::UsageError)
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
          expect { venom.generate_raw_payload }.to_not raise_error
          output = stderr.string
          output.should include("LHOST")
          output.should include("LPORT")
        end
        context "and some datastore options" do
          it "should print options" do
            venom.parse_args %w! -o -p windows/meterpreter/reverse_tcp LPORT=1234!
            expect { venom.generate_raw_payload }.to_not raise_error
            output = stderr.string
            output.should include("LHOST")
            output.should match(/LPORT\s+1234/)
          end

          it "should print options case-insensitively" do
            venom.parse_args %w! -o -p windows/meterpreter/reverse_tcp lPoRt=1234!
            expect { venom.generate_raw_payload }.to_not raise_error
            output = stderr.string
            output.should include("LHOST")
            output.should match(/LPORT\s+1234/)
          end
        end
      end

      context "and an invalid payload" do
        let(:args) { %w! -o -p asdf! }
        it "should raise" do
          expect { venom.generate_raw_payload }.to raise_error(MsfVenom::UsageError)
        end
      end

    end

    [
      { :format => "elf", :arch => "x86" },
      { :format => "raw", :arch => "x86" },
      { :format => "elf", :arch => "armle" },
      { :format => "raw", :arch => "armle" },
      { :format => "elf", :arch => "ppc" },
      { :format => "raw", :arch => "ppc" },
      { :format => "elf", :arch => "mipsle" },
      { :format => "raw", :arch => "mipsle" },
    ].each do |format_hash|
      format = format_hash[:format]
      arch = format_hash[:arch]

      context "building #{format} with linux/#{arch}/shell_bind_tcp" do
        let(:args) { %W! -f #{format} -p linux/#{arch}/shell_bind_tcp ! }
        # We're not encoding, so should be testable here
        it "should contain /bin/sh" do
          output = venom.generate_raw_payload
          # Usually push'd in two instructions, so the whole string
          # isn't all together. Check for the two pieces seperately.
          # Also should have into account payloads using imm16 moves.
          output.should include("sh")
          output.should include("bi")
        end
      end

    end

  end

  describe "#generate" do
    include_context 'Msf::Util::Exe'

    before { venom.parse_args(args) }

    context "with --list" do

      context "with invalid module type" do
        let(:args) { %w!--list asdf! }
        it "should raise UsageError" do
          expect { venom.generate }.to raise_error(MsfVenom::UsageError)
        end
      end

      [ "nop", "encoder", "payload" ].each do |type|
        context "#{type}s" do
          let(:args) { %W!--list #{type}s! }
          it_behaves_like "#{type} dumper" do
            let(:dump) do
              venom.generate
              stderr.string
            end
          end
        end
      end

    end

    context "with invalid datastore option" do
      let(:args) { %w!-f exe -p windows/shell_reverse_tcp LPORT=asdf! }
      it "should fail validation" do
        expect { venom.generate }.to raise_error(Msf::OptionValidateError)
      end
    end

    context "without required datastore option" do
      # Requires LHOST
      let(:args) { %w!-f exe -p windows/shell_reverse_tcp! }
      it "should fail validation" do
        expect { venom.generate }.to raise_error(Msf::OptionValidateError)
      end
    end

    @platform_format_map.each do |plat, formats|
      formats.each do |format_hash|
        format = format_hash[:format]
        arch = format_hash[:arch]
        # Need a new context for each so the let() will work correctly
        context "with format=#{format} platform=#{plat} arch=#{arch}" do
          # This will build executables with no payload. They won't work
          # of course, but at least we can see that it is producing the
          # correct file format for the given arch and platform.
          let(:args) { %W! -p - -f #{format} -a #{arch} --platform #{plat} ! }
          it "should print a #{format} to stdout" do
            venom.generate
            output = stdout.string
            verify_bin_fingerprint(format_hash, output)
          end
        end
      end
    end

  end

end
