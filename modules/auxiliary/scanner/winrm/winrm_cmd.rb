##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/winrm/connection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell

  def initialize
    super(
      'Name'           => 'WinRM Command Runner',
      'Description'    => %q{
        This module runs arbitrary Windows commands using the WinRM Service
        },
      'Author'         => [ 'thelightcosine', 'smashery' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('CMD', [ true, "The windows command to run", "ipconfig /all" ]),
        OptString.new('USERNAME', [ true, "The username to authenticate as"]),
        OptString.new('PASSWORD', [ true, "The password to authenticate with"])
      ])
  end

  def run_host(ip)
    rhost = datastore['RHOST']
    rport = datastore['RPORT']
    uri = datastore['URI']
    ssl = datastore['SSL']
    schema = ssl ? 'https' : 'http'
    endpoint = "#{schema}://#{rhost}:#{rport}#{uri}"
    conn = Net::MsfWinRM::RexWinRMConnection.new(
                endpoint: endpoint,
                host: rhost,
                port: rport,
                uri: uri,
                ssl: ssl,
                user: datastore['USERNAME'],
                password: datastore['PASSWORD'],
                transport: :rex,
                :no_ssl_peer_verification => true,
                :operation_timeout => 1,
                :retry_delay => 1
            )


    if datastore['CreateSession']
      shell = conn.shell(:stdin)
      # Coerce a message to be sent; will throw an exception if it fails
      shell.send_stdin('')
      session_setup(shell,rhost,rport,endpoint)
    else
      begin
        shell = conn.shell(:powershell)
        path = store_loot("winrm.cmd_results", "text/plain", ip, nil, "winrm_cmd_results.txt", "WinRM CMD Results")
        f = File.open(path,'wb')
        output = shell.run(datastore['CMD']) do |stdout,stderr|
          stdout&.each_line do |line|
            print_line(line.rstrip!)
            f.puts(stdout)
          end
          print_error(stderr) if stderr
        end
        f.close
        print_good "Results saved to #{path}"
      rescue
        File.delete(path)
        raise
      ensure
        shell.close
      end
    end
  end

  def session_setup(shell,rhost,rport,endpoint)
    sess = Msf::Sessions::WinrmCommandShell.new(shell,rhost,rport)
    sess.platform = 'windows'
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    info = "WinRM #{username}:#{password} (#{shell.owner})"
    merge_me = {
      'USERNAME' => username,
      'PASSWORD' => password
    }

    start_session(self, info, merge_me,false,nil,sess)
  end

  def start_session(obj, info, ds_merge, crlf = false, sock = nil, sess = nil)
    sess.set_from_exploit(obj)
    sess.info = info

    # Clean up the stored data
    sess.exploit_datastore.merge!(ds_merge)

    framework.sessions.register(sess)
    sess.process_autoruns(datastore)

    # Notify the framework that we have a new session opening up...
    # Don't let errant event handlers kill our session
    begin
      framework.events.on_session_open(sess)
    rescue ::Exception => e
      wlog("Exception in on_session_open event handler: #{e.class}: #{e}")
      wlog("Call Stack\n#{e.backtrace.join("\n")}")
    end

    sess
  end

end

