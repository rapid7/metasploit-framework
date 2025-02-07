require 'rex'
require 'rex/post/meterpreter/extensions/stdapi/constants'

lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  include Msf::Post::DNS::ResolveHost

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Meterpreter resolve_host test',
        'Description' => %q{ This module will test the meterpreter resolve_host API },
        'License' => MSF_LICENSE,
        'Platform' => [ 'windows', 'linux', 'unix', 'java', 'osx' ],
        'SessionTypes' => ['meterpreter', 'shell', 'powershell']
      )
    )
  end

  def test_resolve_host
    vprint_status('Starting resolve_host tests')

    it 'should return a Hash' do
      hostname = 'localhost'
      family = AF_INET6

      resolved_host = resolve_host(hostname, family)
      resolved_host.is_a?(Hash)
    end

    it 'should return a valid IPV4 host' do
      hostname = 'localhost'
      family = AF_INET

      resolved_host = resolve_host(hostname, family)
      if resolved_host[:ips].empty?
        false
      else
        matches = resolved_host[:ips].map do |ip|
          !!(ip =~ Resolv::IPv4::Regex)
        end

        matches.all?(true)
      end
    end

    it 'should return a valid IPV6 host' do
      hostname = 'localhost'
      family = AF_INET6

      resolved_host = resolve_host(hostname, family)
      if resolved_host[:ips].empty?
        false
      else
        matches = resolved_host[:ips].map do |ip|
          !!(ip =~ Resolv::IPv6::Regex)
        end

        matches.all?(true)
      end
    end

    it 'should handle an invalid IPV4 host' do
      hostname = 'foo.bar'
      family = AF_INET

      begin
        resolve_host(hostname, family)
      rescue Rex::Post::Meterpreter::RequestError => e
        e.instance_of?(Rex::Post::Meterpreter::RequestError)
      end
    end

    it 'should handle an invalid IPV6 host' do
      hostname = 'foo.bar'
      family = AF_INET6

      begin
        resolve_host(hostname, family)
      rescue Rex::Post::Meterpreter::RequestError => e
        e.instance_of?(Rex::Post::Meterpreter::RequestError)
      end
    end
  end
end
