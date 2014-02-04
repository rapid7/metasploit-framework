require 'spec_helper'
require 'msf/core/payload_generator'

describe Msf::PayloadGenerator do

  PAYLOAD_FRAMEWORK = Msf::Simple::Framework.create(
      :module_types => [  ::Msf::MODULE_PAYLOAD, ::Msf::MODULE_ENCODER, ::Msf::MODULE_NOP],
      'DisableDatabase' => true,
      'DisableLogging' => true
  )

  let(:lhost) { "192.168.172.1"}
  let(:lport) { "8443" }
  let(:datastore) { { "LHOST" => lhost, "LPORT" => lport } }
  let(:add_code) { false }
  let(:arch) { "x86" }
  let(:badchars) { "\x20\x0D\x0A" }
  let(:encoder)  { 'x86/shikata_ga_nai' }
  let(:format) { "raw" }
  let(:framework) { PAYLOAD_FRAMEWORK }
  let(:iterations) { 1 }
  let(:keep) { false }
  let(:nops) { 0 }
  let(:payload) { "windows/meterpreter/reverse_tcp"}
  let(:platform) { "Windows" }
  let(:space) { 1073741824 }
  let(:stdin) { nil }
  let(:template) { File.join(Msf::Config.data_directory, "templates", "template_x86_windows.exe") }
  let(:generator_opts) {
    {
        add_code: add_code,
        arch: arch,
        badchars: badchars,
        encoder: encoder,
        datastore: datastore,
        format: format,
        framework: framework,
        iterations: iterations,
        keep: keep,
        nops: nops,
        payload: payload,
        platform: platform,
        space: space,
        stdin: stdin,
        template: template
    }
  }
  let(:payload_module) { framework.payloads.create(payload)}
  let(:shellcode) { "\x50\x51\x58\x59" }
  let(:encoder_module) { framework.encoders.create('x86/shikata_ga_nai') }

  subject(:payload_generator) { described_class.new(generator_opts) }

  it { should respond_to :add_code }
  it { should respond_to :arch }
  it { should respond_to :badchars }
  it { should respond_to :encoder }
  it { should respond_to :datastore }
  it { should respond_to :format }
  it { should respond_to :framework }
  it { should respond_to :iterations }
  it { should respond_to :keep }
  it { should respond_to :nops }
  it { should respond_to :payload }
  it { should respond_to :platform }
  it { should respond_to :space }
  it { should respond_to :stdin }
  it { should respond_to :template }

  context 'when creating a new generator' do
    subject(:new_payload_generator) { -> { described_class.new(generator_opts) } }

    context 'when not given a framework instance' do
      let(:generator_opts) {
        {
            add_code: add_code,
            arch: arch,
            badchars: badchars,
            encoder: encoder,
            datastore: datastore,
            format: format,
            iterations: iterations,
            keep: keep,
            nops: nops,
            payload: payload,
            platform: platform,
            space: space,
            stdin: stdin,
            template: template
        }
      }

      it { should raise_error(KeyError, "key not found: :framework") }
    end

    context 'when not given a payload' do
      let(:payload) { nil }

      it { should raise_error(ArgumentError, "Invalid Payload Selected") }
    end

    context 'when given an invalid payload' do
      let(:payload) { "beos/meterpreter/reverse_gopher" }

      it { should raise_error(ArgumentError, "Invalid Payload Selected") }
    end

    context 'when given a payload through stdin' do
      let(:payload) { "stdin" }

      it { should_not raise_error }
    end

    context 'when given an invalid format' do
      let(:format) { "foobar" }

      it { should raise_error(ArgumentError, "Invalid Format Selected") }
    end

    context 'when given any valid transform format' do
      let(:format) { ::Msf::Simple::Buffer.transform_formats.sample }

      it { should_not raise_error }
    end

    context 'when given any valid executable format' do
      let(:format) { ::Msf::Util::EXE.to_executable_fmt_formats.sample }

      it { should_not raise_error }
    end
  end

  context 'when not given a platform' do
    let(:platform) { '' }

    context '#platform_list' do
      it 'returns an empty PlatformList' do
        expect(payload_generator.platform_list.platforms).to be_empty
      end
    end

    context '#choose_platform' do
      it 'chooses the platform list for the module' do
        expect(payload_generator.choose_platform(payload_module).platforms).to eq [Msf::Module::Platform::Windows]
      end

      it 'sets the platform attr to the first platform of the module' do
        my_generator = payload_generator
        my_generator.choose_platform(payload_module)
        expect(my_generator.platform).to eq "Windows"
      end
    end

  end

  context 'when given an invalid platform' do
    let(:platform) { 'foobar' }

    context '#platform_list' do
      it 'returns an empty PlatformList' do
        expect(payload_generator.platform_list.platforms).to be_empty
      end
    end

    context '#choose_platform' do
      it 'chooses the platform list for the module' do
        expect(payload_generator.choose_platform(payload_module).platforms).to eq [Msf::Module::Platform::Windows]
      end
    end

  end

  context 'when given a valid platform' do

    context '#platform_list' do
      it 'returns a PlatformList containing the Platform class' do
        expect(payload_generator.platform_list.platforms.first).to eq Msf::Module::Platform::Windows
      end
    end

    context '#choose_platform' do
      context 'when the chosen platform matches the module' do
        it 'returns the PlatformList for the selected platform' do
          expect(payload_generator.choose_platform(payload_module).platforms).to eq payload_generator.platform_list.platforms
        end
      end

      context 'when the chosen platform and module do not match' do
        let(:platform) { "linux" }
        it 'returns an empty PlatformList' do
          expect(payload_generator.choose_platform(payload_module).platforms).to be_empty
        end
      end
    end

  end

  context '#choose_arch' do
    context 'when no arch is selected' do
      let(:arch) { '' }

      it 'returns the first arch of the module' do
        expect(payload_generator.choose_arch(payload_module)).to eq "x86"
      end

      it 'sets the arch to match the module' do
        my_generator = payload_generator
        my_generator.choose_arch(payload_module)
        expect(my_generator.arch).to eq "x86"
      end
    end

    context 'when the arch matches the module' do
      it 'returns the selected arch' do
        expect(payload_generator.choose_arch(payload_module)).to eq arch
      end
    end

    context 'when the arch does not match the module' do
      let(:arch) { "mipsle" }

      it "returns nil" do
        expect(payload_generator.choose_arch(payload_module)).to be_nil
      end
    end
  end

  context '#generate_raw_payload' do

    context 'when passing a payload through stdin' do
      let(:stdin) { "\x90\x90\x90"}
      let(:payload) { "stdin" }

      context 'when no arch has been selected' do
        let(:arch) { '' }

        it 'raises an IncompatibleArch error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::IncompatibleArch, "You must select an arch for a custom payload")
        end
      end

      context 'when no platform has been selected' do
        let(:platform) { '' }

        it 'raises an IncompatiblePlatform error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::IncompatiblePlatform, "You must select a platform for a custom payload")
        end
      end

      it 'returns the payload from stdin' do
        expect(payload_generator.generate_raw_payload).to eq stdin
      end
    end

    context 'when selecting a metasploit payload' do
      context 'when the platform is incompatible with the payload' do
        let(:platform) { "linux" }

        it 'raises an IncompatiblePlatform error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::IncompatiblePlatform, "The selected platform is incompatible with the payload")
        end
      end

      context 'when the arch is incompatible with the payload' do
        let(:arch) { "mipsle" }

        it 'raises an IncompatibleArch error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::IncompatibleArch, "The selected arch is incompatible with the payload")
        end
      end

      context 'when one or more datastore options are missing' do
        let(:datastore) { {} }

        it 'should raise an error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::OptionValidateError)
        end
      end

      it 'returns the raw bytes of the payload' do
        expect(payload_generator.generate_raw_payload).to be_present
      end
    end
  end

  context '#add_shellcode' do

    context 'when add_code is empty' do
      it 'returns the original shellcode' do
        expect(payload_generator.add_shellcode(shellcode)).to eq shellcode
      end
    end

    context 'when add_code points to a valid file' do
      let(:add_code) { File.join(FILE_FIXTURES_PATH, "nop_shellcode.bin")}

      context 'but platform is not Windows' do
        let(:platform) { "Linux" }

        it 'returns the original shellcode' do
          expect(payload_generator.add_shellcode(shellcode)).to eq shellcode
        end
      end

      context 'but arch is not x86' do
        let(:arch) { "x86_64" }

        it 'returns the original shellcode' do
          expect(payload_generator.add_shellcode(shellcode)).to eq shellcode
        end
      end

      it 'returns modified shellcode' do
        # The exact length is variable due to random nops inserted into the routine
        # It looks like it should always be > 300
        # Can't do precise output matching due to this same issue
        expect(payload_generator.add_shellcode(shellcode).length).to be > 300
      end
    end

    context 'when add_code points to an invalid file' do
      let(:add_code) { "gurfjhfdjhfdsjhfsdvfverf444" }
      it 'raises an error' do
        expect{payload_generator.add_shellcode(shellcode)}.to raise_error(Errno::ENOENT)
      end
    end
  end

  context '#prepend_nops' do
    context 'when nops are set to 0' do
      it 'returns the unmodified shellcode' do
        expect(payload_generator.prepend_nops(shellcode)).to eq shellcode
      end
    end

    context 'when nops are set to more than 0' do
      let(:nops) { 20 }

      it 'returns shellcode of the correct size' do
        expect(payload_generator.prepend_nops(shellcode).length).to eq 24
      end

      it 'puts the nops in front of the original shellcode' do
        expect(payload_generator.prepend_nops(shellcode)[20,24]).to eq shellcode
      end
    end
  end

  context '#get_encoders' do
    let(:encoder_names) { ["Polymorphic XOR Additive Feedback Encoder", "Alpha2 Alphanumeric Mixedcase Encoder" ] }

    context 'when an encoder is selected' do
      it 'returns an array' do
        expect(payload_generator.get_encoders).to be_kind_of Array
      end

      it 'returns an array with only one element' do
        expect(payload_generator.get_encoders.count).to eq 1
      end

      it 'returns the correct encoder in the array' do
        expect(payload_generator.get_encoders.first.name).to eq encoder_names[0]
      end
    end

    context 'when multiple encoders are selected' do
      let(:encoder) { "x86/shikata_ga_nai,x86/alpha_mixed"}

      it 'returns an array of the right size' do
        expect(payload_generator.get_encoders.count).to eq 2
      end

      it 'returns each of the selected encoders in the array' do
        payload_generator.get_encoders.each do |my_encoder|
          expect(encoder_names).to include my_encoder.name
        end
      end

      it 'returns the encoders in order of rank high to low' do
        expect(payload_generator.get_encoders[0].rank).to be > payload_generator.get_encoders[1].rank
      end
    end

    context 'when no encoder is selected but badchars are present' do
      let(:encoder) { '' }

      it 'returns an array of all encoders with a compatible arch' do
        payload_generator.get_encoders.each do |my_encoder|
          expect(my_encoder.arch).to include arch
        end
      end
    end

    context 'when no encoder or badchars are selected' do
      let(:encoder) { '' }
      let(:badchars) { '' }

      it 'returns an empty array' do
        expect(payload_generator.get_encoders).to be_empty
      end
    end
  end

  context '#run_encoder' do

    it 'should call the encoder a number of times equal to the iterations' do
      my_encoder = encoder_module
      my_encoder.should_receive(:encode).exactly(iterations).times.and_return(shellcode)
      payload_generator.run_encoder(my_encoder, shellcode)
    end

    context 'when the encoder makes a buffer too large' do
      let(:space) { 4 }
      it 'should raise an error' do
        expect{payload_generator.run_encoder(encoder_module, shellcode)}.to raise_error(Msf::EncoderSpaceViolation, "encoder has made a buffer that is too big")
      end
    end
  end

  context '#format_payload' do
    context 'when format is js_be' do
      let(:format) { "js_be"}
      context 'and arch is x86' do
        it 'should raise an IncompatibleEndianess error' do
          expect{payload_generator.format_payload(shellcode)}.to raise_error(Msf::IncompatibleEndianess, "Big endian format selected for a non big endian payload")
        end
      end
    end

    context 'when format is a transform format' do
      let(:format) { 'c' }

      it 'applies the appropriate transform format' do
        ::Msf::Simple::Buffer.should_receive(:transform).with(shellcode, format)
        payload_generator.format_payload(shellcode)
      end
    end

    context 'when format is an executable format' do
      let(:format) { 'exe' }

      it 'applies the appropriate executable format' do
        ::Msf::Util::EXE.should_receive(:to_executable_fmt).with(framework, arch, platform, shellcode, format, payload_generator.exe_options)
        payload_generator.format_payload(shellcode)
      end
    end
  end



end