require 'spec_helper'
require 'msf/core/payload_generator'

RSpec.describe Msf::PayloadGenerator do
  include_context 'Msf::Simple::Framework#modules loading'

  # let(:lhost) { "192.168.172.1"}
  # let(:lport) { "8443" }
  # let(:datastore) { { "LHOST" => lhost, "LPORT" => lport } }
  # let(:add_code) { false }
  # let(:arch) { "x86" }
  # let(:badchars) { "\x20\x0D\x0A" }
  # let(:encoder_reference_name)  {
  #   # use encoder_module to ensure it is loaded prior to passing to generator
  #   encoder_module.refname
  # }
  # let(:format) { "raw" }
  # let(:iterations) { 1 }
  # let(:keep) { false }
  # let(:nops) { 0 }
  # let(:payload_reference_name) {
  #   # use payload_module to ensure it is loaded prior to passing to generator
  #   payload_module.refname
  # }
  # let(:platform) { "Windows" }
  # let(:space) { 1073741824 }
  # let(:stdin) { nil }
  # let(:template) { File.join(Msf::Config.data_directory, "templates", "template_x86_windows.exe") }

  let(:generator_opts) {
    {
        add_code: false,
        arch: 'x86',
        badchars: "\x20\x0D\x0A",
        encoder:  'x86/shikata_ga_nai',
        datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
        format: 'raw',
        framework: framework,
        iterations: 1,
        keep: false,
        nops: 0,
        payload: 'windows/meterpreter/reverse_tcp',
        platform: 'Windows',
        space: 1073741824,
        stdin: nil,
        template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
    }
  }

  let!(:payload_module) {
    load_and_create_module(
        ancestor_reference_names: %w{
          stagers/windows/reverse_tcp
          stages/windows/meterpreter
        },
        module_type: 'payload',
        reference_name: 'windows/meterpreter/reverse_tcp'
    )
  }

  # let(:shellcode) { "\x50\x51\x58\x59" }

  # let(:var_name) { 'buf' }

  subject(:payload_generator) {
    Msf::PayloadGenerator.new(generator_opts)
  }

  it { is_expected.to respond_to :add_code }
  it { is_expected.to respond_to :arch }
  it { is_expected.to respond_to :badchars }
  it { is_expected.to respond_to :cli }
  it { is_expected.to respond_to :encoder }
  it { is_expected.to respond_to :datastore }
  it { is_expected.to respond_to :format }
  it { is_expected.to respond_to :framework }
  it { is_expected.to respond_to :iterations }
  it { is_expected.to respond_to :keep }
  it { is_expected.to respond_to :nops }
  it { is_expected.to respond_to :payload }
  it { is_expected.to respond_to :platform }
  it { is_expected.to respond_to :space }
  it { is_expected.to respond_to :stdin }
  it { is_expected.to respond_to :template }


  context 'when creating a new generator' do
    subject(:new_payload_generator) { -> { described_class.new(generator_opts) } }

    context 'when not given a framework instance' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it { is_expected.to raise_error(KeyError, 'key not found: :framework') }
    end

    context 'when not given a payload' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: nil,
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it { is_expected.to raise_error(ArgumentError, "Invalid Payload Selected") }
    end

    context 'when given an invalid payload' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'beos/meterpreter/reverse_gopher',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it { is_expected.to raise_error(ArgumentError, "Invalid Payload Selected") }
    end

    context 'when given a payload through stdin' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'stdin',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it { is_expected.not_to raise_error }
    end

    context 'when given an invalid format' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'foobar',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it { is_expected.to raise_error(ArgumentError, "Invalid Format Selected") }
    end

    context 'when given any valid transform format' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: ::Msf::Simple::Buffer.transform_formats.sample,
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it { is_expected.not_to raise_error }
    end

    context 'when given any valid executable format' do
      let(:format) { ::Msf::Util::EXE.to_executable_fmt_formats.sample }
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: ::Msf::Util::EXE.to_executable_fmt_formats.sample,
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it { is_expected.not_to raise_error }
    end
  end

  context 'when not given a platform' do
    let(:generator_opts) {
      {
          add_code: false,
          arch: 'x86',
          badchars: "\x20\x0D\x0A",
          encoder:  'x86/shikata_ga_nai',
          datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
          format: 'raw',
          framework: framework,
          iterations: 1,
          keep: false,
          nops: 0,
          payload: 'windows/meterpreter/reverse_tcp',
          platform: '',
          space: 1073741824,
          stdin: nil,
          template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
      }
    }

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
    let(:generator_opts) {
      {
          add_code: false,
          arch: 'x86',
          badchars: "\x20\x0D\x0A",
          encoder:  'x86/shikata_ga_nai',
          datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
          format: 'raw',
          framework: framework,
          iterations: 1,
          keep: false,
          nops: 0,
          payload: 'windows/meterpreter/reverse_tcp',
          platform: 'foobar',
          space: 1073741824,
          stdin: nil,
          template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
      }
    }

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
        let(:generator_opts) {
          {
              add_code: false,
              arch: 'x86',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'windows/meterpreter/reverse_tcp',
              platform: 'linux',
              space: 1073741824,
              stdin: nil,
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }
        it 'returns an empty PlatformList' do
          expect(payload_generator.choose_platform(payload_module).platforms).to be_empty
        end
      end
    end

  end

  context '#choose_arch' do
    context 'when no arch is selected' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: '',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

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
        expect(payload_generator.choose_arch(payload_module)).to eq 'x86'
      end
    end

    context 'when the arch does not match the module' do
      let(:arch) { "mipsle" }
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'mipsle',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it "returns nil" do
        expect(payload_generator.choose_arch(payload_module)).to be_nil
      end
    end
  end

  context '#generate_raw_payload' do

    context 'when passing a payload through stdin' do
      context 'when no arch has been selected' do
        let(:generator_opts) {
          {
              add_code: false,
              arch: '',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'stdin',
              platform: 'Windows',
              space: 1073741824,
              stdin: "\x90\x90\x90",
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }

        it 'raises an IncompatibleArch error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::IncompatibleArch, "You must select an arch for a custom payload")
        end
      end

      context 'when no platform has been selected' do
        let(:generator_opts) {
          {
              add_code: false,
              arch: 'x86',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'stdin',
              platform: '',
              space: 1073741824,
              stdin: "\x90\x90\x90",
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }
        it 'raises an IncompatiblePlatform error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::IncompatiblePlatform, "You must select a platform for a custom payload")
        end
      end

      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'stdin',
            platform: 'Windows',
            space: 1073741824,
            stdin: "\x90\x90\x90",
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      it 'returns the payload from stdin' do
        expect(payload_generator.generate_raw_payload).to eq "\x90\x90\x90"
      end
    end

    context 'when selecting a metasploit payload' do
      context 'when the platform is incompatible with the payload' do
        let(:generator_opts) {
          {
              add_code: false,
              arch: 'x86',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'windows/meterpreter/reverse_tcp',
              platform: 'linux',
              space: 1073741824,
              stdin: "\x90\x90\x90",
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }

        it 'raises an IncompatiblePlatform error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::IncompatiblePlatform, "The selected platform is incompatible with the payload")
        end
      end

      context 'when the arch is incompatible with the payload' do
        let(:generator_opts) {
          {
              add_code: false,
              arch: 'mipsle',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'windows/meterpreter/reverse_tcp',
              platform: 'Windows',
              space: 1073741824,
              stdin: "\x90\x90\x90",
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }
        it 'raises an IncompatibleArch error' do
          expect{payload_generator.generate_raw_payload}.to raise_error(Msf::IncompatibleArch, "The selected arch is incompatible with the payload")
        end
      end

      context 'when one or more datastore options are missing' do
        let(:generator_opts) {
          {
              add_code: false,
              arch: 'x86',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: {} ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'windows/meterpreter/reverse_tcp',
              platform: 'Windows',
              space: 1073741824,
              stdin: "\x90\x90\x90",
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }
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
    let(:shellcode) { "\x50\x51\x58\x59" }
    context 'when add_code is empty' do
      it 'returns the original shellcode' do
        expect(payload_generator.add_shellcode(shellcode)).to eq shellcode
      end
    end

    context 'when add_code points to a valid file' do
      context 'but platform is not Windows' do
        let(:generator_opts) {
          {
              add_code: File.join(FILE_FIXTURES_PATH, "nop_shellcode.bin"),
              arch: 'x86',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'windows/meterpreter/reverse_tcp',
              platform: 'Linux',
              space: 1073741824,
              stdin: nil,
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }

        it 'returns the original shellcode' do
          expect(payload_generator.add_shellcode(shellcode)).to eq shellcode
        end
      end

      context 'but arch is not x86' do
        let(:generator_opts) {
          {
              add_code: File.join(FILE_FIXTURES_PATH, "nop_shellcode.bin"),
              arch: 'x64',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'windows/meterpreter/reverse_tcp',
              platform: 'Windows',
              space: 1073741824,
              stdin: nil,
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }


        it 'returns the original shellcode' do
          expect(payload_generator.add_shellcode(shellcode)).to eq shellcode
        end
      end


      it 'returns modified shellcode' do
        skip "This is a bad test and needs to be refactored"
        # The exact length is variable due to random nops inserted into the routine
        # It looks like it should always be > 300
        # Can't do precise output matching due to this same issue
        expect(payload_generator.add_shellcode(shellcode).length).to be > 300
      end
    end

    context 'when add_code points to an invalid file' do
      let(:generator_opts) {
        {
            add_code: "gurfjhfdjhfdsjhfsdvfverf444",
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      it 'raises an error' do
        expect{payload_generator.add_shellcode(shellcode)}.to raise_error(Errno::ENOENT)
      end
    end
  end

  context '#prepend_nops' do
    let(:shellcode) { "\x50\x51\x58\x59" }
    context 'when nops are set to 0' do
      before(:example) do
        load_and_create_module(
            module_type: 'nop',
            reference_name: 'x86/opty2'
        )
      end

      it 'returns the unmodified shellcode' do
        expect(payload_generator.prepend_nops(shellcode)).to eq shellcode
      end
    end

    context 'when nops are set to more than 0' do
      before(:example) do
        load_and_create_module(
            module_type: 'nop',
            reference_name: 'x86/opty2'
        )
      end
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: '',
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 20,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      context 'when payload is x86' do

        it 'returns shellcode of the correct size' do
          final = payload_generator.prepend_nops(shellcode)
          expect(final.length).to eq 24
        end

        it 'puts the nops in front of the original shellcode' do
          expect(payload_generator.prepend_nops(shellcode)[20,24]).to eq shellcode
        end

      end

      context 'when payload is Windows x64' do
        let(:generator_opts) {
          {
              add_code: false,
              arch: 'x64',
              badchars: '',
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 20,
              payload: 'windows/x64/meterpreter/reverse_tcp',
              platform: 'Windows',
              space: 1073741824,
              stdin: nil,
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }

        before(:example) do
          load_and_create_module(
              module_type: 'nop',
              reference_name: 'x64/simple'
          )
          load_and_create_module(
            ancestor_reference_names: %w{
                stagers/windows/x64/reverse_tcp
                stages/windows/x64/meterpreter
            },
            module_type: 'payload',
            reference_name: 'windows/x64/meterpreter/reverse_tcp'
          )
        end

        it 'returns shellcode of the correct size' do
          final = payload_generator.prepend_nops(shellcode)
          expect(final.length).to eq(20 + shellcode.length)
        end

        it 'puts the nops in front of the original shellcode' do
          final = payload_generator.prepend_nops(shellcode)
          expect(final[20, 20 + shellcode.length]).to eq shellcode
        end

      end
    end
  end

  context '#get_encoders' do
    let!(:encoder_module) {
      load_and_create_module(
          module_type: 'encoder',
          reference_name: 'x86/shikata_ga_nai'
      )
    }
    let(:encoder_names) { ["Polymorphic XOR Additive Feedback Encoder", "Alpha2 Alphanumeric Mixedcase Encoder" ] }
    let(:generator_opts) {
      {
          add_code: false,
          arch: 'x86',
          badchars: "\x20\x0D\x0A",
          encoder:  'x86/shikata_ga_nai',
          datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
          format: 'raw',
          framework: framework,
          iterations: 1,
          keep: false,
          nops: 0,
          payload: 'windows/meterpreter/reverse_tcp',
          platform: 'Windows',
          space: 1073741824,
          stdin: nil,
          template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
      }
    }
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
      #
      # lets
      #

      # let(:encoder_reference_name) {
      #   encoder_reference_names.join(',')
      # }
      #
      # let(:encoder_reference_names) {
      #   %w{
      #     x86/shikata_ga_nai
      #     x86/alpha_mixed
      #   }
      # }

      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai,x86/alpha_mixed',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      before(:example) do
        load_and_create_module(
            module_type: 'encoder',
            reference_name: 'x86/alpha_mixed'
        )
      end

      it 'returns an array of the right size' do
        expect(payload_generator.get_encoders.count).to eq 2
      end

      it 'returns each of the selected encoders in the array' do
        payload_generator.get_encoders.each do |msf_encoder|
          expect(encoder_names).to include msf_encoder.name
        end
      end

      it 'returns the encoders in order of rank high to low' do
        expect(payload_generator.get_encoders[0].rank).to be > payload_generator.get_encoders[1].rank
      end
    end

    context 'when no encoder is selected but badchars are present' do
      # let(:encoder_reference_name) { '' }
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  '',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it 'returns an array of all encoders with a compatible arch' do
        payload_generator.get_encoders.each do |my_encoder|
          expect(my_encoder.arch).to include 'x86'
        end
      end
    end

    context 'when no encoder or badchars are selected' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: '',
            encoder:  '',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      let(:encoder_module) {
          load_and_create_module(
              module_type: 'encoder',
              reference_name: 'x86/shikata_ga_nai'
          )
        }

      it 'returns an empty array' do
        expect(payload_generator.get_encoders).to be_empty
      end
    end
  end

  context '#run_encoder' do
    let(:shellcode) { "\x50\x51\x58\x59" }
    let(:encoder_module) {
        load_and_create_module(
            module_type: 'encoder',
            reference_name: 'x86/shikata_ga_nai'
        )
      }
    it 'should call the encoder a number of times equal to the iterations' do
      expect(encoder_module).to receive(:encode).exactly(1).times.and_return(shellcode)
      payload_generator.run_encoder(encoder_module, shellcode)
    end

    context 'when the encoder makes a buffer too large' do
      # let(:space) { 4 }
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 4,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      it 'should raise an error' do
        expect{payload_generator.run_encoder(encoder_module, shellcode)}.to raise_error(Msf::EncoderSpaceViolation, "encoder has made a buffer that is too big")
      end
    end
  end

  context '#format_payload' do
    let(:shellcode) { "\x50\x51\x58\x59" }
    context 'when format is js_be' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'js_be',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      context 'and arch is x86' do
        it 'should raise an IncompatibleEndianess error' do
          expect{payload_generator.format_payload(shellcode)}.to raise_error(Msf::IncompatibleEndianess, "Big endian format selected for a non big endian payload")
        end
      end
    end

    context 'when format is a transform format' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'c',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      it 'applies the appropriate transform format' do
        expect(::Msf::Simple::Buffer).to receive(:transform).with(shellcode, 'c', 'buf', {})
        payload_generator.format_payload(shellcode)
      end
    end

    context 'when format is an executable format' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'exe',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      it 'applies the appropriate executable format' do
        expect(::Msf::Util::EXE).to receive(:to_executable_fmt).with(framework, 'x86', kind_of(payload_generator.platform_list.class), shellcode, 'exe', payload_generator.exe_options)
        payload_generator.format_payload(shellcode)
      end
    end
  end

  context '#generate_java_payload' do
    context 'when format is war' do
      context 'if the payload is a valid java payload' do
        let(:generator_opts) {
          {
              add_code: false,
              arch: 'x86',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'war',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'java/meterpreter/reverse_tcp',
              platform: 'Windows',
              space: 1073741824,
              stdin: nil,
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }
        let(:payload_module) {
          load_and_create_module(
              ancestor_reference_names: %w{
                stagers/java/reverse_tcp
                stages/java/meterpreter
              },
              module_type: 'payload',
              reference_name: 'java/meterpreter/reverse_tcp'
          )
        }

        it 'calls the generate_war on the payload' do
          allow(framework).to receive_message_chain(:payloads, :keys).and_return ['java/meterpreter/reverse_tcp']
          allow(framework).to receive_message_chain(:payloads, :create).and_return(payload_module)
          expect(payload_module).to receive(:generate_war).and_call_original
          payload_generator.generate_java_payload
        end
      end

      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'war',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      it 'raises an InvalidFormat exception' do
        expect{ payload_generator.generate_java_payload }.to raise_error(Msf::InvalidFormat)
      end
    end

    context 'when format is raw' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'java/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }

      context 'if the payload responds to generate_jar' do
        let!(:payload_module) {
          load_and_create_module(
              ancestor_reference_names: %w{
                stagers/java/reverse_tcp
                stages/java/meterpreter
              },
              module_type: 'payload',
              reference_name: 'java/meterpreter/reverse_tcp'
          )
        }

        it 'calls the generate_jar on the payload' do
          allow(framework).to receive_message_chain(:payloads, :keys).and_return ['java/meterpreter/reverse_tcp']
          allow(framework).to receive_message_chain(:payloads, :create).and_return(payload_module)
          expect(payload_module).to receive(:generate_jar).and_call_original
          payload_generator.generate_java_payload
        end
      end

      context 'if the payload does not respond to generate_jar' do
        let!(:payload_module) {
          load_and_create_module(
              ancestor_reference_names: %w{
                singles/java/jsp_shell_reverse_tcp
              },
              module_type: 'payload',
              reference_name: 'java/jsp_shell_reverse_tcp'
          )
        }
        let(:generator_opts) {
          {
              add_code: false,
              arch: 'x86',
              badchars: "\x20\x0D\x0A",
              encoder:  'x86/shikata_ga_nai',
              datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
              format: 'raw',
              framework: framework,
              iterations: 1,
              keep: false,
              nops: 0,
              payload: 'java/jsp_shell_reverse_tcp',
              platform: 'Windows',
              space: 1073741824,
              stdin: nil,
              template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
          }
        }

        it 'calls #generate' do
          allow(framework).to receive_message_chain(:payloads, :keys).and_return ['java/jsp_shell_reverse_tcp']
          allow(framework).to receive_message_chain(:payloads, :create).and_return(payload_module)
          expect(payload_module).to receive(:generate).and_call_original
          payload_generator.generate_java_payload
        end
      end



    end

    context 'when format is a non-java format' do
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'exe',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'windows/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      it 'raises an InvalidFormat exception' do
        expect{payload_generator.generate_java_payload}.to raise_error(Msf::InvalidFormat)
      end
    end
  end

  context '#generate_payload' do
    let!(:encoder_module) {
      load_and_create_module(
          module_type: 'encoder',
          reference_name: 'x86/shikata_ga_nai'
      )
    }
    let(:generator_opts) {
      {
          add_code: false,
          arch: 'x86',
          badchars: "\x20\x0D\x0A",
          encoder:  'x86/shikata_ga_nai',
          datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
          format: 'raw',
          framework: framework,
          iterations: 1,
          keep: false,
          nops: 0,
          payload: 'windows/meterpreter/reverse_tcp',
          platform: 'Windows',
          space: 1073741824,
          stdin: nil,
          template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
      }
    }
    it 'calls each step of the process' do
      expect(payload_generator).to receive(:generate_raw_payload).and_call_original
      expect(payload_generator).to receive(:add_shellcode).and_call_original
      expect(payload_generator).to receive(:encode_payload).and_call_original
      expect(payload_generator).to receive(:prepend_nops).and_call_original
      expect(payload_generator).to receive(:format_payload).and_call_original
      payload_generator.generate_payload
    end

    context 'when the payload is java' do
      let!(:payload_module) {
        load_and_create_module(
            ancestor_reference_names: %w{
                stagers/java/reverse_tcp
                stages/java/meterpreter
              },
            module_type: 'payload',
            reference_name: 'java/meterpreter/reverse_tcp'
        )
      }
      let(:generator_opts) {
        {
            add_code: false,
            arch: 'x86',
            badchars: "\x20\x0D\x0A",
            encoder:  'x86/shikata_ga_nai',
            datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
            format: 'raw',
            framework: framework,
            iterations: 1,
            keep: false,
            nops: 0,
            payload: 'java/meterpreter/reverse_tcp',
            platform: 'Windows',
            space: 1073741824,
            stdin: nil,
            template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
        }
      }
      it 'calls generate_java_payload' do
        expect(payload_generator).to receive(:generate_java_payload).and_call_original
        payload_generator.generate_payload
      end
    end
  end
  context 'when the payload exceeds the specified space' do
    let(:generator_opts) {
      {
          add_code: false,
          arch: 'x86',
          badchars: "\x20\x0D\x0A",
          encoder:  nil,
          datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
          format: 'raw',
          framework: framework,
          iterations: 1,
          keep: false,
          nops: 0,
          payload: 'windows/meterpreter/reverse_tcp',
          platform: 'Windows',
          space: 100,
          stdin: nil,
          template: File.join(Msf::Config.data_directory, 'templates', 'template_x86_windows.exe')
      }
    }
    it 'should raise an error' do
      expect{payload_generator.generate_payload}.to raise_error(Msf::PayloadSpaceViolation, "The payload exceeds the specified space")
    end
  end
  context 'when the payload format is invalid for the platform' do
    let!(:payload_module) {
      load_and_create_module(
          ancestor_reference_names: %w{
              stagers/osx/x86/reverse_tcp
              stages/osx/x86/isight
            },
          module_type: 'payload',
          reference_name: 'osx/x86/isight/reverse_tcp'
      )
    }
    let(:generator_opts) {
      {
          datastore: { 'LHOST' => '192.168.172.1', 'LPORT' => '8443' } ,
          format: 'elf',
          framework: framework,
          keep: false,
          payload: 'osx/x86/isight/reverse_tcp',
          stdin: nil,
      }
    }
    it 'should raise an error' do
      expect{payload_generator.generate_payload}.to raise_error(Msf::PayloadGeneratorError, "The payload could not be generated, check options")
    end
  end

end
