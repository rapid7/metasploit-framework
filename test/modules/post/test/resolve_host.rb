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
      hostname = 'google.com'
      family = AF_INET
      does_not_support_local_resolution = ['php']

      if does_not_support_local_resolution.include?(session.arch) && session.platform.eql?('windows') && hostname == 'localhost'
        vprint_status("test skipped for #{session.arch} - local DNS resolution not available")
      else
        resolved_host = resolve_host(hostname, family)
        resolved_host.is_a?(Hash)
      end
    end

    it 'should return a valid IPV4 host' do
      hostname = 'google.com'
      family = AF_INET
      does_not_support_local_resolution = ['php']

      if does_not_support_local_resolution.include?(session.arch) && session.platform.eql?('windows') && hostname == 'localhost'
        vprint_status("test skipped for #{session.arch} - local DNS resolution not available")
      else
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
    end

    it 'should return a valid IPV6 host' do
      hostname = 'google.com'
      family = AF_INET6
      does_not_support_ipv6_resolution = %w[python java x64 x86]
      does_not_support_local_resolution = ['php']

      print_status(session.arch)
      print_status(session.platform)

      if does_not_support_ipv6_resolution.include?(session.arch) && session.platform.eql?('windows')
        vprint_status("test skipped for #{session.arch} - IPV6 DNS resolution not available")
      elsif does_not_support_local_resolution.include?(session.arch) && session.platform.eql?('windows') && hostname == 'localhost'
        vprint_status("test skipped for #{session.arch} - local DNS resolution not available")
      else
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
