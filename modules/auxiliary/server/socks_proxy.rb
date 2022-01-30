##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'SOCKS Proxy Server',
      'Description' => %q{
        This module provides a SOCKS proxy server that uses the builtin Metasploit routing to relay connections.
      },
      'Author' => [ 'sf', 'Spencer McIntyre', 'surefire' ],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Proxy', { 'Description' => 'Run a SOCKS proxy server' } ]
      ],
      'PassiveActions' => [
        'Proxy'
      ],
      'DefaultAction' => 'Proxy'
    )

    register_options([
      OptString.new('SRVHOST', [true, 'The address to listen on', '0.0.0.0']),
      OptPort.new('SRVPORT', [true, 'The port to listen on', 1080]),
      OptEnum.new('VERSION', [ true, 'The SOCKS version to use', '5', %w[4a 5] ]),
      OptString.new('USERNAME', [false, 'Proxy username for SOCKS5 listener'], conditions: %w[VERSION == 5]),
      OptString.new('PASSWORD', [false, 'Proxy password for SOCKS5 listener'], conditions: %w[VERSION == 5]),
    ])
  end

  def setup
    super
    @mutex = ::Mutex.new
    @socks_proxy = nil
  end

  def cleanup
    @mutex.synchronize do
      if @socks_proxy
        print_status('Stopping the SOCKS proxy server')
        @socks_proxy.stop
        @socks_proxy = nil
      end
    end
    super
  end

  def run
    opts = {
      'ServerHost' => datastore['SRVHOST'],
      'ServerPort' => datastore['SRVPORT'],
      'Context' => { 'Msf' => framework, 'MsfExploit' => self }
    }

    if datastore['VERSION'] == '5'
      opts.merge!({
        'ServerUsername' => datastore['USERNAME'],
        'ServerPassword' => datastore['PASSWORD']
      })
      @socks_proxy = Rex::Proto::Proxy::Socks5::Server.new(opts)
    elsif datastore['VERSION'] == '4a'
      @socks_proxy = Rex::Proto::Proxy::Socks4a.new(opts)
    end

    print_status('Starting the SOCKS proxy server')
    @socks_proxy.start
    @socks_proxy.join
  end
end
