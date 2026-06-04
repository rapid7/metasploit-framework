require 'rspec'

RSpec.describe 'cmd/linux/http/x64' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'cmd/linux/http/x64/meterpreter_reverse_tcp',
      ancestor_reference_names: [
        'adapters/cmd/linux/http/x64',
        'singles/linux/x64/meterpreter_reverse_tcp'
      ]
    )
  end

  let(:lhost)           { '192.168.1.100' }
  let(:lport)           { '4444' }
  let(:fetch_srvhost)   { '192.168.1.100' }
  let(:fetch_srvport)   { 8080 }
  let(:fetch_uripath)   { 'testpayload' }
  let(:fetch_filename)  { 'payload' }
  let(:fetch_writable_dir) { './' }

  let(:datastore_values) do
    {
      'LHOST'             => lhost,
      'LPORT'             => lport,
      'FETCH_SRVHOST'     => fetch_srvhost,
      'FETCH_SRVPORT'     => fetch_srvport,
      'FETCH_URIPATH'     => fetch_uripath,
      'FETCH_FILENAME'    => fetch_filename,
      'FETCH_WRITABLE_DIR' => fetch_writable_dir,
      'FETCH_FILELESS'    => 'none',
      'FETCH_PIPE'        => false
    }
  end

  before(:each) { subject.datastore.merge!(datastore_values) }

  # ---------------------------------------------------------------------------
  # Module metadata
  # ---------------------------------------------------------------------------

  describe 'module metadata' do
    it 'includes HTTP Fetch in the name' do
      expect(subject.name).to include('HTTP Fetch')
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
    it 'returns HTTP' do
      expect(subject.fetch_protocol).to eq('HTTP')
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
        reference_name: 'cmd/linux/http/x64/meterpreter_reverse_tcp',
        ancestor_reference_names: [
          'adapters/cmd/linux/http/x64',
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

    %w[CERTUTIL POWERSHELL].each do |cmd|
      it "rejects #{cmd} as an invalid value" do
        expect(subject.options['FETCH_COMMAND'].valid?(cmd)).to be(false)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # generate_fetch_commands
  # ---------------------------------------------------------------------------

  describe '#generate_fetch_commands' do
    context 'with CURL' do
      before { subject.datastore['FETCH_COMMAND'] = 'CURL' }

      it 'uses curl -so to download' do
        expect(subject.generate_fetch_commands).to include('curl -so')
      end

      it 'includes the HTTP URL with host, port, and URI path' do
        expect(subject.generate_fetch_commands).to include(
          "http://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end

      it 'writes to the configured filename' do
        expect(subject.generate_fetch_commands).to include(fetch_filename)
      end

      it 'makes the file executable and runs it' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('chmod +x')
        expect(cmd).to include("#{fetch_writable_dir}#{fetch_filename}&")
      end
    end

    context 'with WGET' do
      before { subject.datastore['FETCH_COMMAND'] = 'WGET' }

      it 'uses wget -qO to download' do
        expect(subject.generate_fetch_commands).to include('wget -qO')
      end

      it 'includes the HTTP URL' do
        expect(subject.generate_fetch_commands).to include(
          "http://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end
    end

    context 'with GET' do
      before { subject.datastore['FETCH_COMMAND'] = 'GET' }

      it 'uses GET -m GET to download' do
        expect(subject.generate_fetch_commands).to include('GET -m GET')
      end

      it 'includes the HTTP URL' do
        expect(subject.generate_fetch_commands).to include(
          "http://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end

      it 'uses tee to write the file instead of shell redirection' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('| tee')
        expect(cmd).not_to match(/GET -m GET[^|]+>(?!\s*\/dev\/null)/)
      end
    end

    context 'with TNFTP' do
      before { subject.datastore['FETCH_COMMAND'] = 'TNFTP' }

      it 'uses tnftp -Vo to download' do
        expect(subject.generate_fetch_commands).to include('tnftp -Vo')
      end

      it 'includes the HTTP URL' do
        expect(subject.generate_fetch_commands).to include(
          "http://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end
    end

    context 'with FTP' do
      before { subject.datastore['FETCH_COMMAND'] = 'FTP' }

      it 'uses ftp -Vo to download' do
        expect(subject.generate_fetch_commands).to include('ftp -Vo')
      end

      it 'includes the HTTP URL' do
        expect(subject.generate_fetch_commands).to include(
          "http://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
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

      it 'pipes curl stdout to sh' do
        cmd = subject.generate_pipe_command(pipe_uri)
        expect(cmd).to match(/curl -s http:\/\/.+\|sh/)
      end

      it 'includes the pipe URI in the URL' do
        expect(subject.generate_pipe_command(pipe_uri)).to include(pipe_uri)
      end
    end

    context 'with WGET' do
      before { subject.datastore['FETCH_COMMAND'] = 'WGET' }

      it 'pipes wget stdout to sh' do
        cmd = subject.generate_pipe_command(pipe_uri)
        expect(cmd).to match(/wget -qO- http:\/\/.+\|sh/)
      end
    end

    context 'with GET' do
      before { subject.datastore['FETCH_COMMAND'] = 'GET' }

      it 'pipes GET stdout to sh' do
        cmd = subject.generate_pipe_command(pipe_uri)
        expect(cmd).to match(/GET -m GET http:\/\/.+\|sh/)
      end
    end
  end
end
