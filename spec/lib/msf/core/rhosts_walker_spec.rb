# -*- coding:binary -*-

require 'spec_helper'

RSpec::Matchers.define :have_datastore_values do |expected|
  match do |enumerator|
    http_options_for(enumerator) == expected
  end

  failure_message do |mod|
    "\nexpected:\n#{expected.join(",\n")}\n\ngot:\n#{http_options_for(mod).join(",\n")}\n\n(compared using ==)\n"
  end

  failure_message_when_negated do |_actual|
    "\nexpected: value != #{expected.inspect}\n\ngot: #{actual.inspect}\n\n(compared using ==)\n"
  end

  def http_options_for(datastores)
    http_keys = %w[RHOSTS RPORT VHOST SSL HttpUsername HttpPassword TARGETURI URI]
    smb_keys = %w[RHOSTS RPORT SMBDomain SMBUser SMBPass SMBSHARE RPATH]
    mysql_keys = %w[RHOSTS RPORT USERNAME PASSWORD]
    postgres_keys = %w[RHOSTS RPORT USERNAME PASSWORD DATABASE]
    ssh_keys = %w[RHOSTS RPORT USERNAME PASSWORD]
    required_keys = http_keys + smb_keys + mysql_keys + postgres_keys + ssh_keys
    datastores.map do |datastore|
      # Workaround: Manually convert the datastore to a hash ourselves as `datastore.to_h` coerces all datatypes into strings
      # which prevents this test suite from validating types correctly. i.e. The tests need to ensure that RPORT is correctly
      # set as an integer class etc.
      datastore_hash = datastore.keys.each_with_object({}) { |key, hash| hash[key] = datastore[key] }

      # Slice the datastore options that we care about, ignoring other values that just add noise such as VERBOSE/WORKSPACE/etc.
      datastore_hash.slice(*required_keys)
    end
  end
end

RSpec::Matchers.define :match_errors do |expected|
  match do |actual|
    return false if actual.count != expected.count

    expected.zip(actual).all? do |(expected, actual)|
      actual.instance_of?(expected.class) && actual.message == expected.message
    end
  end

  failure_message do |actual|
    "\nexpected:\n#{expected.to_a.join(",\n")}\n\ngot:\n#{actual.to_a.join(",\n")}\n\n(compared using ==)\n"
  end

  failure_message_when_negated do |_actual|
    "\nexpected: value != #{expected.inspect}\n\ngot: #{actual.inspect}\n\n(compared using ==)\n"
  end
  description do
    "match_errors #{expected.inspect}"
  end
end

RSpec.describe Msf::RhostsWalker do
  let(:aux_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      def initialize
        super(
          'Name' => 'mock module',
          'Description' => 'mock module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )

        register_options(
          [
            Msf::Opt::RHOSTS,
            Msf::Opt::RPORT(3000),
          ]
        )
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(nil)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    mod
  end

  let(:http_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::HttpClient

      def initialize
        super(
          'Name' => 'mock http module',
          'Description' => 'mock http module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )

        register_options(
          [
            Msf::Opt::RHOSTS,
            Msf::Opt::RPORT(3000),
            Msf::OptString.new('TARGETURI', [true, 'Path to application', '/default_app'])
          ]
        )
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(nil)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    mod
  end

  let(:mysql_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::MYSQL

      def initialize
        super(
          'Name' => 'mock mysql module',
          'Description' => 'mock mysql module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )

        register_options(
          [
            Msf::OptString.new('DATABASE', [true, 'The database to use', 'information_schema'])
          ]
        )
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(nil)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    mod
  end

  let(:postgres_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::Postgres

      def initialize
        super(
          'Name' => 'mock postgres module',
          'Description' => 'mock postgres module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(nil)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    mod
  end

  let(:ssh_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      include Msf::Auxiliary::AuthBrute
      include Msf::Exploit::Remote::SSH::Options

      def initialize
        super(
          'Name' => 'mock ssh module',
          'Description' => 'mock ssh module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(nil)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    mod
  end

  let(:smb_scanner_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::DCERPC
      include Msf::Exploit::Remote::SMB::Client

      # Scanner mixin should be near last
      include Msf::Auxiliary::Scanner
      include Msf::Auxiliary::Report

      def initialize
        super(
          'Name' => 'mock smb module',
          'Description' => 'mock smb module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )

        deregister_options('RPORT')
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(nil)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    mod
  end

  let(:smb_share_mod) do
    mod_klass = Class.new(Msf::Auxiliary) do
      include Msf::Exploit::Remote::DCERPC
      include Msf::Exploit::Remote::SMB::Client
      include Msf::Exploit::Remote::SMB::Client::RemotePaths

      def initialize
        super(
          'Name' => 'mock smb share module',
          'Description' => 'mock smb share module',
          'Author' => ['Unknown'],
          'License' => MSF_LICENSE
        )

        register_options(
          [
            Msf::OptString.new('SMBSHARE', [true, 'Target share', 'default_share_value']),
          ]
        )
      end
    end

    mod = mod_klass.new
    datastore = Msf::ModuleDataStore.new(mod)
    allow(mod).to receive(:framework).and_return(nil)
    mod.send(:datastore=, datastore)
    datastore.import_options(mod.options)
    mod
  end

  def each_host_for(mod)
    replicant = mod.replicant
    described_class.new(replicant.datastore['RHOSTS'], replicant.datastore).to_enum
  end

  def each_error_for(mod)
    replicant = mod.replicant
    described_class.new(replicant.datastore['RHOSTS']).to_enum(:errors).to_a
  end

  before(:each) do
    @temp_files = []

    allow(::Addrinfo).to receive(:getaddrinfo).with('example.com', 0, ::Socket::AF_UNSPEC, ::Socket::SOCK_STREAM) do |*_args|
      [::Addrinfo.new(['AF_INET', 0, 'example.com', '192.0.2.2'])]
    end
    allow(::Addrinfo).to receive(:getaddrinfo).with('www.example.com', 0, ::Socket::AF_UNSPEC, ::Socket::SOCK_STREAM) do |*_args|
      [::Addrinfo.new(['AF_INET', 0, 'www.example.com', '233.252.0.0'])]
    end
    allow(::Addrinfo).to receive(:getaddrinfo).with('multiple_ips.example.com', 0, ::Socket::AF_UNSPEC, ::Socket::SOCK_STREAM) do |*_args|
      [
        ::Addrinfo.new(['AF_INET', 0, 'multiple_ips.example.com', '198.51.100.1']),
        ::Addrinfo.new(['AF_INET', 0, 'multiple_ips.example.com', '203.0.113.1']),
      ]
    end
  end

  def create_tempfile(content)
    file = Tempfile.new
    @temp_files << file
    file.write(content)
    file.flush

    file.path
  end

  after do
    @temp_files.each(&:unlink)
  end

  describe '#valid?' do
    context 'when the input is valid' do
      [
        { 'RHOSTS' => '127.0.0.1' },
        { 'RHOSTS' => '127.0.0.0/30' },
        { 'RHOSTS' => 'https://example.com:9000/foo' },
        { 'RHOSTS' => 'cidr:/30:https://user:pass@multiple_ips.example.com:9000/foo' },
        { 'RHOSTS' => '"http://user:this is a password@multiple_ips.example.com:9000/foo"' },
      ].each do |test|
        it "validates #{test['RHOSTS']} as being valid" do
          expect(described_class.new(test['RHOSTS']).valid?).to be true
          expect(described_class.new(test['RHOSTS'], aux_mod.datastore).valid?).to be true
        end
      end
    end

    context 'when the input is invalid' do
      [
        {},
        { 'RHOSTS' => nil },
        { 'RHOSTS' => '' },
        { 'RHOSTS' => '-1' },
        { 'RHOSTS' => 'http:|' },
        { 'RHOSTS' => '127.0.0.1 http:' },
        { 'RHOSTS' => '127.0.0.1 http: 127.0.0.1' },
        { 'RHOSTS' => '"http://127.0.0.1' },
        { 'RHOSTS' => 'unknown_protocol://127.0.0.1' },
      ].each do |test|
        it "validates #{test['RHOSTS']} as being invalid" do
          expect(described_class.new(test['RHOSTS']).valid?).to be false
          expect(described_class.new(test['RHOSTS'], aux_mod.datastore).valid?).to be false
        end
      end
    end
  end

  describe '#count' do
    [
      # Happy paths
      { 'RHOSTS' => '127.0.0.1', 'expected' => 1 },
      { 'RHOSTS' => '127.0.0.0/30', 'expected' => 4 },
      { 'RHOSTS' => 'https://example.com:9000/foo', 'expected' => 1 },
      { 'RHOSTS' => 'cidr:/30:https://user:pass@multiple_ips.example.com:9000/foo', 'expected' => 8 },

      # Edge cases
      { 'expected' => 0 },
      { 'RHOSTS' => nil, 'expected' => 0 },
      { 'RHOSTS' => '', 'expected' => 0 },
      { 'RHOSTS' => '-1', 'expected' => 0 },
      { 'RHOSTS' => 'http:|', 'expected' => 0 },
      { 'RHOSTS' => '127.0.0.1 http:|', 'expected' => 1 },
      { 'RHOSTS' => '127.0.0.1 http:| 127.0.0.1', 'expected' => 2 },
      { 'RHOSTS' => '127.0.0.1 unknown_protocol://127.0.0.1 ftpz://127.0.0.1', 'expected' => 1 },
    ].each do |test|
      it "counts #{test['RHOSTS'].inspect} as being #{test['expected']}" do
        expect(described_class.new(test['RHOSTS'], aux_mod.datastore).count).to eq(test['expected'])
      end
    end
  end

  describe '#errors' do
    [
      # Happy paths
      { 'RHOSTS' => '127.0.0.1', 'expected' => [] },
      { 'RHOSTS' => '127.0.0.0/30', 'expected' => [] },
      { 'RHOSTS' => 'https://example.com:9000/foo', 'expected' => [] },
      { 'RHOSTS' => 'cidr:/30:https://user:pass@multiple_ips.example.com:9000/foo', 'expected' => [] },

      # Edge cases
      { 'expected' => [] },
      { 'RHOSTS' => nil, 'expected' => [] },
      { 'RHOSTS' => '', 'expected' => [] },
      { 'RHOSTS' => '-1', 'expected' => [] },
      { 'RHOSTS' => 'http:', 'expected' => [Msf::RhostsWalker::Error.new('http:')] },
      { 'RHOSTS' => '127.0.0.1 http:', 'expected' => [Msf::RhostsWalker::Error.new('http:')] },
      { 'RHOSTS' => '127.0.0.1 http: 127.0.0.1 https:', 'expected' => [Msf::RhostsWalker::Error.new('http:'), Msf::RhostsWalker::Error.new('https:')] },
      # Unknown protocols aren't validated, as there may be potential ambiguity over ipv6 addresses
      # which may technically start with a 'schema': AAA:1450:4009:822::2004. The existing rex socket
      # range walker will silently drop this value though, and it may be treated as an overall error.
      { 'RHOSTS' => 'unknown_protocol://127.0.0.1 127.0.0.1', 'expected' => [ ] },

      # cidr validation
      { 'RHOSTS' => 'cidr:127.0.0.1', 'expected' => [Msf::RhostsWalker::Error.new('cidr:127.0.0.1')] },
      { 'RHOSTS' => 'cidr:abc/127.0.0.1', 'expected' => [Msf::RhostsWalker::Error.new('cidr:abc/127.0.0.1')] },
      { 'RHOSTS' => 'cidr:/1000:127.0.0.1', 'expected' => [Msf::RhostsWalker::Error.new('cidr:/1000:127.0.0.1')] },
      { 'RHOSTS' => 'cidr:%eth2:127.0.0.1', 'expected' => [Msf::RhostsWalker::Error.new('cidr:%eth2:127.0.0.1')] },
    ].each do |test|
      it "handles the input #{test['RHOSTS'].inspect} as having the errors #{test['expected']}" do
        aux_mod.datastore['RHOSTS'] = test['RHOSTS']
        expect(each_error_for(aux_mod)).to match_errors(test['expected'])
      end
    end
  end

  describe '#each' do
    it 'enumerates nil rhosts gracefully' do
      aux_mod.datastore['RHOSTS'] = nil
      expected = [
      ]
      expect(each_host_for(aux_mod)).to have_datastore_values(expected)
    end

    it 'enumerates empty rhosts gracefully' do
      aux_mod.datastore['RHOSTS'] = ''
      expected = [
      ]
      expect(each_host_for(aux_mod)).to have_datastore_values(expected)
    end

    it 'enumerates RHOSTS with a single ip' do
      aux_mod.datastore['RHOSTS'] = '127.0.0.1'
      expected = [
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000 }
      ]
      expect(each_host_for(aux_mod)).to have_datastore_values(expected)
    end

    it 'enumerates multiple RHOSTS separated by spaces' do
      aux_mod.datastore['RHOSTS'] = '127.0.0.1 127.0.0.2 127.0.0.3'
      expected = [
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000 },
        { 'RHOSTS' => '127.0.0.2', 'RPORT' => 3000 },
        { 'RHOSTS' => '127.0.0.3', 'RPORT' => 3000 },
      ]
      expect(each_host_for(aux_mod)).to have_datastore_values(expected)
    end

    it 'enumerates a single ipv4 address range' do
      aux_mod.datastore['RHOSTS'] = '127.0.0.0/30'
      expected = [
        { 'RHOSTS' => '127.0.0.0', 'RPORT' => 3000 },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000 },
        { 'RHOSTS' => '127.0.0.2', 'RPORT' => 3000 },
        { 'RHOSTS' => '127.0.0.3', 'RPORT' => 3000 }
      ]
      expect(each_host_for(aux_mod)).to have_datastore_values(expected)
    end

    it 'enumerates a single file value' do
      temp_file = create_tempfile("127.0.0.0\n127.0.0.1")
      aux_mod.datastore['RHOSTS'] = "file:#{temp_file}"
      expected = [
        { 'RHOSTS' => '127.0.0.0', 'RPORT' => 3000 },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000 },
      ]
      expect(each_host_for(aux_mod)).to have_datastore_values(expected)
    end

    it 'enumerates a single http value' do
      http_mod.datastore['RHOSTS'] = 'http://www.example.com/foo'
      expected = [
        { 'RHOSTS' => '233.252.0.0', 'RPORT' => 80, 'VHOST' => 'www.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates resolving a single http value to multiple ip addresses' do
      http_mod.datastore['RHOSTS'] = 'http://multiple_ips.example.com/foo'
      expected = [
        { 'RHOSTS' => '198.51.100.1', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.1', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates http values with user/passwords' do
      http_mod.datastore.import_options(
        Msf::OptionContainer.new(
          [
            Msf::OptString.new('HttpUsername', [true, 'The username to authenticate as', 'admin']),
            Msf::OptString.new('HttpPassword', [true, 'The password for the specified username', 'admin'])
          ]
        ),
        http_mod.class,
        true
      )
      http_mod.datastore['RHOSTS'] = 'http://example.com/ http://user@example.com/ http://user:password@example.com http://:@example.com'
      expected = [
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'admin', 'HttpPassword' => 'admin', 'TARGETURI' => '/' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'admin', 'TARGETURI' => '/' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'password', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates a query string containing commas' do
      http_mod.datastore['RHOSTS'] = 'http://multiple_ips.example.com/foo?filter=a,b,c'
      expected = [
        { 'RHOSTS' => '198.51.100.1', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.1', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'handles values wrapped in quotes as atomic values' do
      http_mod.datastore['RHOSTS'] = '127.0.0.1 "http://user:this is a password@example.com" http://user:password@example.com'
      expected = [
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'this is a password', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'password', 'TARGETURI' => '/default_app' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'Handles HttpUsername and HttpPassword being registered again, but with nil values' do
      http_mod.datastore.import_options(
        Msf::OptionContainer.new(
          [
            Msf::OptString.new('HttpPassword', [true, 'The username to authenticate as', 'admin']),
            Msf::OptString.new('HttpPassword', [true, 'The password for the specified username', 'admin'])
          ]
        ),
        http_mod.class,
        true
      )
      http_mod.datastore['RHOSTS'] = '127.0.0.1 https://example.com "http://user:this is a password@example.com" http://user:password@example.com http://user:password@example.com/ http://user:password@example.com/path'
      expected = [
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => 'admin', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 443, 'VHOST' => 'example.com', 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => 'admin', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'this is a password', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'password', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'password', 'TARGETURI' => '/' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'password', 'TARGETURI' => '/path' }
      ]

      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'preferences setting user/passwords fields over basic auth credentials' do
      http_mod.datastore.import_options(
        Msf::OptionContainer.new(
          [
            Msf::OptString.new('HttpUsername', [ false, 'The username to authenticate as' ]),
            Msf::OptString.new('HttpPassword', [ false, 'The password for the specified username' ]),
          ]
        ),
        http_mod.class,
        true
      )

      http_mod.datastore['RHOSTS'] = 'http://example.com/ http://example.com/ http://user@example.com/ http://user:password@example.com http://:@example.com'
      expected = [
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => nil, 'HttpPassword' => nil, 'TARGETURI' => '/' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => nil, 'HttpPassword' => nil, 'TARGETURI' => '/' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => nil, 'TARGETURI' => '/' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'password', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates a cidr scheme with a single http value' do
      http_mod.datastore['RHOSTS'] = 'cidr:/30:http://127.0.0.1:3000/foo/bar'
      expected = [
        { 'RHOSTS' => '127.0.0.0', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo/bar' },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo/bar' },
        { 'RHOSTS' => '127.0.0.2', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo/bar' },
        { 'RHOSTS' => '127.0.0.3', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo/bar' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates a cidr scheme with a domain' do
      http_mod.datastore['RHOSTS'] = 'cidr:/30:https://example.com:8080/foo/bar'
      expected = [
        { 'RHOSTS' => '192.0.2.0', 'RPORT' => 8080, 'VHOST' => 'example.com', 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo/bar' },
        { 'RHOSTS' => '192.0.2.1', 'RPORT' => 8080, 'VHOST' => 'example.com', 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo/bar' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 8080, 'VHOST' => 'example.com', 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo/bar' },
        { 'RHOSTS' => '192.0.2.3', 'RPORT' => 8080, 'VHOST' => 'example.com', 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo/bar' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates a cidr scheme with a domain with multiple ip addresses' do
      http_mod.datastore['RHOSTS'] = 'cidr:/30:http://multiple_ips.example.com/foo'
      expected = [
        { 'RHOSTS' => '198.51.100.0', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '198.51.100.1', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '198.51.100.2', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '198.51.100.3', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.0', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.1', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.2', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.3', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates a file with http values' do
      temp_file = create_tempfile("https://www.example.com/\n127.0.0.1")
      http_mod.datastore['RHOSTS'] = "file:#{temp_file}"
      expected = [
        { 'RHOSTS' => '233.252.0.0', 'RPORT' => 443, 'VHOST' => 'www.example.com', 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates a cidr scheme with a file' do
      temp_file = create_tempfile("127.0.0.1\n233.252.0.0")
      http_mod.datastore['RHOSTS'] = "cidr:/30:file:#{temp_file}"
      expected = [
        { 'RHOSTS' => '127.0.0.0', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '127.0.0.2', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '127.0.0.3', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '233.252.0.0', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '233.252.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '233.252.0.2', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '233.252.0.3', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates a cidr scheme with a file' do
      temp_file = create_tempfile("127.0.0.1\n233.252.0.0")
      http_mod.datastore['RHOSTS'] = "cidr:/30:file:#{temp_file}"
      expected = [
        { 'RHOSTS' => '127.0.0.0', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '127.0.0.2', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '127.0.0.3', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '233.252.0.0', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '233.252.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '233.252.0.2', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '233.252.0.3', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates multiple ipv6 urls' do
      http_mod.datastore['RHOSTS'] = 'http://[::]:8000/ http://[::ffff:7f00:1]:8000/ http://[::1]:8000/'
      expected = [
        { 'RHOSTS' => '::', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::ffff:7f00:1', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::1', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates cidr scheme with a ipv6 file' do
      temp_file = create_tempfile("http://[::]:8000/\nhttp://[::ffff:7f00:1]:8000/\nhttp://[::1]:8000/")
      http_mod.datastore['RHOSTS'] = "cidr:/127:file:#{temp_file}"
      expected = [
        { 'RHOSTS' => '::', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::1', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::ffff:7f00:0', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::ffff:7f00:1', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::1', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    it 'enumerates cidr scheme with a ipv6 scope' do
      http_mod.datastore['RHOSTS'] = 'cidr:%eth2/127:http://[::]:8000/'
      expected = [
        { 'RHOSTS' => '::%eth2', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::1%eth2', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
      expect(each_error_for(http_mod)).to be_empty
    end

    context 'when using the smb scheme' do
      it 'enumerates smb schemes for scanners when no user or password are specified' do
        smb_scanner_mod.datastore['RHOSTS'] = 'smb://example.com/'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => '', 'SMBPass' => '' }
        ]
        expect(each_host_for(smb_scanner_mod)).to have_datastore_values(expected)
      end

      it 'enumerates smb schemes for scanners when no user or password are specified and uses the default option values instead' do
        smb_scanner_mod.datastore.import_options(
          Msf::OptionContainer.new(
            [
              Msf::OptString.new('SMBUser', [true, 'The username to authenticate as', 'db2admin']),
              Msf::OptString.new('SMBPass', [true, 'The password for the specified username', 'db2admin'])
            ]
          ),
          smb_scanner_mod.class,
          true
        )
        smb_scanner_mod.datastore['RHOSTS'] = 'smb://example.com/ smb://user@example.com/ smb://user:password@example.com smb://:@example.com'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => 'db2admin', 'SMBPass' => 'db2admin' },
          { 'RHOSTS' => '192.0.2.2', 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => 'user', 'SMBPass' => 'db2admin' },
          { 'RHOSTS' => '192.0.2.2', 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => 'user', 'SMBPass' => 'password' },
          { 'RHOSTS' => '192.0.2.2', 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => '', 'SMBPass' => '' }
        ]
        expect(each_host_for(smb_scanner_mod)).to have_datastore_values(expected)
      end

      it 'enumerates smb schemes for scanners when a user and password are specified' do
        smb_scanner_mod.datastore['RHOSTS'] = 'smb://user:pass@example.com/'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'SSL' => false, 'SMBDomain' => '.', 'SMBPass' => 'pass', 'SMBUser' => 'user' }
        ]
        expect(each_host_for(smb_scanner_mod)).to have_datastore_values(expected)
      end

      it 'enumerates smb schemes for scanners when a domain, user and password are specified' do
        smb_scanner_mod.datastore['RHOSTS'] = 'smb://domain;user:pass@example.com/'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'SSL' => false, 'SMBDomain' => 'domain', 'SMBPass' => 'pass', 'SMBUser' => 'user' }
        ]
        expect(each_host_for(smb_scanner_mod)).to have_datastore_values(expected)
      end

      it 'enumerates smb schemes for ' do
        smb_scanner_mod.datastore['RHOSTS'] = 'smb://domain;user:pass@example.com/'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'SSL' => false, 'SMBDomain' => 'domain', 'SMBPass' => 'pass', 'SMBUser' => 'user' }
        ]
        expect(each_host_for(smb_scanner_mod)).to have_datastore_values(expected)
      end

      it 'enumerates smb schemes for when the module has SMBSHARE and RPATHS available' do
        smb_share_mod.datastore['RHOSTS'] = 'smb://user@example.com smb://user@example.com/ smb://user@example.com/share_name smb://user@example.com/share_name/path/to/file.txt'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 445, 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => 'user', 'SMBPass' => '', 'SMBSHARE' => 'default_share_value', 'RPATH' => nil },
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 445, 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => 'user', 'SMBPass' => '', 'SMBSHARE' => 'default_share_value', 'RPATH' => nil },
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 445, 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => 'user', 'SMBPass' => '', 'SMBSHARE' => 'share_name', 'RPATH' => '' },
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 445, 'SSL' => false, 'SMBDomain' => '.', 'SMBUser' => 'user', 'SMBPass' => '', 'SMBSHARE' => 'share_name', 'RPATH' => 'path/to/file.txt' }
        ]
        expect(each_host_for(smb_share_mod)).to have_datastore_values(expected)
      end
    end

    # According to the URI grammar, the userinfo non-terminal symbol should not contain spaces, or reserved
    # characters such as `@` etc. To provide a nicer user experience, we try to gloss over this implementation detail,
    # so users can copy arbitrary password values and it should work as expected
    # https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
    #
    # Note that by default the Ruby URI module honors the semantics of this specification, whilst Addressable::URI handles
    # this scenario in a more intuitive way for end users
    context 'when userinfo contains reserved characters ' do
      it 'handles complex passwords' do
        http_mod.datastore['RHOSTS'] = '"http://user:a b c p4$$w0rd@123@!@example.com/"'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 80, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'a b c p4$$w0rd@123@!', 'TARGETURI' => '/' }
        ]
        expect(each_error_for(http_mod)).to be_empty
        expect(each_host_for(http_mod)).to have_datastore_values(expected)
      end
    end

    context 'when using the mysql scheme' do
      it 'enumerates mysql schemes' do
        mysql_mod.datastore['RHOSTS'] = 'mysql://mysql:@example.com "mysql://user:a b c@example.com/" "mysql://user:a+b+c=@example.com:9001/database_name"'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 3306, 'SSL' => false, 'USERNAME' => 'mysql', 'PASSWORD' => '', 'DATABASE' => 'information_schema' },
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 3306, 'SSL' => false, 'USERNAME' => 'user', 'PASSWORD' => 'a b c', 'DATABASE' => 'information_schema' },
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 9001, 'SSL' => false, 'USERNAME' => 'user', 'PASSWORD' => 'a+b+c=', 'DATABASE' => 'database_name' }
        ]
        expect(each_error_for(mysql_mod)).to be_empty
        expect(each_host_for(mysql_mod)).to have_datastore_values(expected)
      end
    end

    context 'when using the postgres scheme' do
      it 'enumerates postgres schemes' do
        postgres_mod.datastore['RHOSTS'] = 'postgres://postgres:@example.com "postgres://user:a b c@example.com/" "postgres://user:a b c@example.com:9001/database_name"'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 5432, 'USERNAME' => 'postgres', 'PASSWORD' => '', 'DATABASE' => 'template1' },
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 5432, 'USERNAME' => 'user', 'PASSWORD' => 'a b c', 'DATABASE' => 'template1' },
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 9001, 'USERNAME' => 'user', 'PASSWORD' => 'a b c', 'DATABASE' => 'database_name' }
        ]
        expect(each_error_for(postgres_mod)).to be_empty
        expect(each_host_for(postgres_mod)).to have_datastore_values(expected)
      end
    end

    context 'when using the ssh scheme' do
      it 'enumerates ssh schemes' do
        ssh_mod.datastore['RHOSTS'] = '"ssh://user:a b c@example.com/"'
        expected = [
          { 'RHOSTS' => '192.0.2.2', 'RPORT' => 22, 'USERNAME' => 'user', 'PASSWORD' => 'a b c' }
        ]
        expect(each_error_for(ssh_mod)).to be_empty
        expect(each_host_for(ssh_mod)).to have_datastore_values(expected)
      end
    end
    # TODO: Discuss adding a test for the datastore containing an existing TARGETURI,and running with a HTTP url without a path. Should the TARGETURI be overridden to '/', '', or unaffected, and the default value is used instead?

    it 'enumerates a combination of all syntaxes' do
      temp_file_a = create_tempfile("\n192.0.2.0\n\n\n127.0.0.5\n\nhttp://user:pass@example.com:9000/foo\ncidr:/30:https://user:pass@multiple_ips.example.com:9000/foo")
      temp_file_b = create_tempfile("https://www.example.com/\n127.0.0.1\ncidr:/31:http://127.0.0.1/tomcat/manager\nfile:#{temp_file_a}")
      http_mod.datastore['RHOSTS'] = "127.0.0.1 cidr:/31:http://192.0.2.0/tomcat/manager https://192.0.2.0:8080/manager/html file:#{temp_file_b}"
      expected = [
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.0', 'RPORT' => 80, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/tomcat/manager' },
        { 'RHOSTS' => '192.0.2.1', 'RPORT' => 80, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/tomcat/manager' },
        { 'RHOSTS' => '192.0.2.0', 'RPORT' => 8080, 'VHOST' => nil, 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/manager/html' },
        { 'RHOSTS' => '233.252.0.0', 'RPORT' => 443, 'VHOST' => 'www.example.com', 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '127.0.0.0', 'RPORT' => 80, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/tomcat/manager' },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 80, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/tomcat/manager' },
        { 'RHOSTS' => '192.0.2.0', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '127.0.0.5', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' },
        { 'RHOSTS' => '192.0.2.2', 'RPORT' => 9000, 'VHOST' => 'example.com', 'SSL' => false, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '198.51.100.0', 'RPORT' => 9000, 'VHOST' => 'multiple_ips.example.com', 'SSL' => true, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '198.51.100.1', 'RPORT' => 9000, 'VHOST' => 'multiple_ips.example.com', 'SSL' => true, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '198.51.100.2', 'RPORT' => 9000, 'VHOST' => 'multiple_ips.example.com', 'SSL' => true, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '198.51.100.3', 'RPORT' => 9000, 'VHOST' => 'multiple_ips.example.com', 'SSL' => true, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.0', 'RPORT' => 9000, 'VHOST' => 'multiple_ips.example.com', 'SSL' => true, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.1', 'RPORT' => 9000, 'VHOST' => 'multiple_ips.example.com', 'SSL' => true, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.2', 'RPORT' => 9000, 'VHOST' => 'multiple_ips.example.com', 'SSL' => true, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.3', 'RPORT' => 9000, 'VHOST' => 'multiple_ips.example.com', 'SSL' => true, 'HttpUsername' => 'user', 'HttpPassword' => 'pass', 'TARGETURI' => '/foo' }
      ]

      expect(each_error_for(http_mod)).to be_empty
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
    end
  end
end
