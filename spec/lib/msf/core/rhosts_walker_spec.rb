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
    datastores.map do |datastore|
      # Slice the datastore options we care about, ignoring other values that just add noise such as VERBOSE/WORKSPACE/etc.
      datastore.to_h.slice(
        'RHOSTS',
        'RPORT',
        'VHOST',
        'SSL',
        'HttpUsername',
        'HttpPassword',
        'TARGETURI',
        'URI'
      )
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
    allow(mod).to receive(:datastore).and_return(datastore)
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
    allow(mod).to receive(:datastore).and_return(datastore)
    datastore.import_options(mod.options)
    mod
  end

  def each_host_for(mod)
    described_class.new(mod.datastore['RHOSTS'], mod.datastore).to_enum
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
        { 'RHOSTS' => '127.0.0.1 http:|' },
        { 'RHOSTS' => '127.0.0.1 http:| 127.0.0.1' },
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

      # # Edge cases
      { 'expected' => [] },
      { 'RHOSTS' => nil, 'expected' => [] },
      { 'RHOSTS' => '', 'expected' => [] },
      { 'RHOSTS' => '-1', 'expected' => [] },
      { 'RHOSTS' => 'http:|', 'expected' => [Msf::RhostsWalker::Error.new('http:|')] },
      { 'RHOSTS' => '127.0.0.1 http:|', 'expected' => [Msf::RhostsWalker::Error.new('http:|')] },
      { 'RHOSTS' => '127.0.0.1 http:| 127.0.0.1', 'expected' => [Msf::RhostsWalker::Error.new('http:|')] },
    ].each do |test|
      it "handles the input #{test['RHOSTS'].inspect} as having the errors #{test['expected']}" do
        expect(described_class.new(test['RHOSTS'], aux_mod.datastore).to_enum(:errors)).to match_errors(test['expected'])
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
    end

    it 'enumerates resolving a single http value to multiple ip addresses' do
      http_mod.datastore['RHOSTS'] = 'http://multiple_ips.example.com/foo'
      expected = [
        { 'RHOSTS' => '198.51.100.1', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' },
        { 'RHOSTS' => '203.0.113.1', 'RPORT' => 80, 'VHOST' => 'multiple_ips.example.com', 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/foo' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
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
    end

    it 'enumerates a file with http values' do
      temp_file = create_tempfile("https://www.example.com/\n127.0.0.1")
      http_mod.datastore['RHOSTS'] = "file:#{temp_file}"
      expected = [
        { 'RHOSTS' => '233.252.0.0', 'RPORT' => 443, 'VHOST' => 'www.example.com', 'SSL' => true, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '127.0.0.1', 'RPORT' => 3000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/default_app' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
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
    end

    it 'enumerates multiple ipv6 urls' do
      http_mod.datastore['RHOSTS'] = 'http://[::]:8000/ http://[::ffff:7f00:1]:8000/ http://[::1]:8000/'
      expected = [
        { 'RHOSTS' => '::', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::ffff:7f00:1', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::1', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
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
    end

    it 'enumerates cidr scheme with a ipv6 scope' do
      http_mod.datastore['RHOSTS'] = 'cidr:%eth2/127:http://[::]:8000/'
      expected = [
        { 'RHOSTS' => '::%eth2', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' },
        { 'RHOSTS' => '::1%eth2', 'RPORT' => 8000, 'VHOST' => nil, 'SSL' => false, 'HttpUsername' => '', 'HttpPassword' => '', 'TARGETURI' => '/' }
      ]
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
    end

    # TODO: Discuss adding a test for the datastore containing an existing TARGETURI,and running with a HTTP url without a path. Should the TARGETURI be overridden to '/', '', or unaffected, and the default value is used instead?
    # TODO: Discuss adding a test for the datastore containing an existing HttpUsername/HttpPassword value, and running with a HTTP url without a specified user/password. Is the user/password an empty string, or the default values?

    it 'enumerates a combination of all syntaxes' do
      temp_file_a = create_tempfile("\n192.0.2.0\n\n\n127.0.0.5\n\nhttp://user:pass@example.com:9000/foo\ncidr:/30:https://user:pass@multiple_ips.example.com:9000/foo")
      temp_file_b = create_tempfile("https://www.example.com/\n127.0.0.1\ncidr:/31:http://127.0.0.1/tomcat/manager\nfile:#{temp_file_a}")
      http_mod.datastore['RHOSTS'] = "127.0.0.1, cidr:/31:http://192.0.2.0/tomcat/manager, https://192.0.2.0:8080/manager/html file:#{temp_file_b}"
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
      expect(each_host_for(http_mod)).to have_datastore_values(expected)
    end
  end
end
