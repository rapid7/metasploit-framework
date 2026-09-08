require 'rspec'

RSpec.describe 'cmd/windows/smb/x64' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'cmd/windows/smb/x64/meterpreter_reverse_tcp',
      ancestor_reference_names: [
        'adapters/cmd/windows/smb/x64',
        'singles/windows/x64/meterpreter_reverse_tcp'
      ]
    )
  end

  let(:lhost)            { '192.168.1.100' }
  let(:lport)            { '4444' }
  let(:fetch_srvhost)    { '192.168.1.100' }
  let(:fetch_uripath)    { 'testshare' }
  let(:fetch_filename)   { 'payload.dll' }

  let(:datastore_values) do
    {
      'LHOST'          => lhost,
      'LPORT'          => lport,
      'FETCH_SRVHOST'  => fetch_srvhost,
      'FETCH_URIPATH'  => fetch_uripath,
      'FETCH_FILENAME' => fetch_filename
    }
  end

  before(:each) { subject.datastore.merge!(datastore_values) }

  describe 'module metadata' do
    it 'includes SMB Fetch in the name' do
      expect(subject.name).to include('SMB Fetch')
    end

    it 'targets the Windows platform' do
      expect(subject.platform.platforms).to include(Msf::Module::Platform::Windows)
    end

    it 'uses CMD arch' do
      expect(subject.arch).to include(ARCH_CMD)
    end

    it 'adapts x64 and not x86 payloads' do
      expect(subject.send(:module_info)['AdaptedArch']).to eq(ARCH_X64)
    end

    it 'has win as the adapted platform' do
      expect(subject.send(:module_info)['AdaptedPlatform']).to eq('win')
    end
  end

  describe 'deregistered options' do
    %w[FETCH_COMMAND FETCH_DELETE FETCH_SRVPORT FETCH_WRITABLE_DIR].each do |opt|
      it "does not expose #{opt}" do
        expect(subject.options.key?(opt)).to be(false)
      end
    end
  end

  describe 'FETCH_FILENAME option' do
    it 'is available' do
      expect(subject.options.key?('FETCH_FILENAME')).to be(true)
    end

    it 'defaults to test.dll' do
      fresh = load_and_create_module(
        module_type: 'payload',
        reference_name: 'cmd/windows/smb/x64/meterpreter_reverse_tcp',
        ancestor_reference_names: [
          'adapters/cmd/windows/smb/x64',
          'singles/windows/x64/meterpreter_reverse_tcp'
        ]
      )
      expect(fresh.datastore['FETCH_FILENAME']).to eq('test.dll')
    end
  end

  describe '#srvport' do
    it 'is hardcoded to 445' do
      expect(subject.srvport).to eq(445)
    end
  end

  describe '#fetch_protocol' do
    it 'returns SMB' do
      expect(subject.fetch_protocol).to eq('SMB')
    end
  end

  describe '#windows?' do
    it 'returns true for this Windows platform module' do
      expect(subject.windows?).to be(true)
    end
  end

  describe '#unc' do
    it 'begins with a double backslash and the server host' do
      expect(subject.unc).to start_with("\\\\#{fetch_srvhost}")
    end

    it 'includes the share name from FETCH_URIPATH' do
      expect(subject.unc).to include("\\#{fetch_uripath}")
    end

    it 'includes the filename from FETCH_FILENAME' do
      expect(subject.unc).to include("\\#{fetch_filename}")
    end

    it 'returns the full UNC path as host\\share\\filename' do
      expect(subject.unc).to eq("\\\\#{fetch_srvhost}\\#{fetch_uripath}\\#{fetch_filename}")
    end
  end

  describe '#generate_fetch_commands' do
    it 'returns a rundll32 command' do
      expect(subject.generate_fetch_commands).to include('rundll32')
    end

    it 'includes the UNC path' do
      expect(subject.generate_fetch_commands).to include(subject.unc)
    end

    it 'calls ordinal 0' do
      expect(subject.generate_fetch_commands).to end_with(',0')
    end

    it 'accepts uri and dynamic_arch keyword arguments without raising' do
      expect { subject.generate_fetch_commands(uri: 'ignored', dynamic_arch: true) }.not_to raise_error
    end
  end
end
