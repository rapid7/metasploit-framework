# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::WMIC

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'WQL Command Runner',
        'Description'   => %q{
          This module will execute a WQL query via Powershell's Get-WmiObject. A WQL query
          can be explicity defined with the WQL and NAMESPACE options, or a hard-coded
          query can be used by defining the an ACTION option. The following ACTIONs are
          available: OSVERSION - Returns information about the operating system,
          PROCESSINFO - Returns running processes, RAW_QUERY - Run a raw WQL query.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Chris Higgins' ], # msf module - @ch1gg1ns
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ],
        'Actions'       =>
        [
          ['OSVERSION'],
          ['PROCESSINFO'],
          ['RAW_QUERY']
        ]
      ))
    register_options(
      [
        OptString.new("ACTION" , [ false, "OSVERSION, PROCESSINFO, or RAW_QUERY", "OSVERSION" ]),
        OptString.new("NAMESPACE" , [ false, "Namespace to run the WQL query against" ]),
        OptString.new("WQL" , [ false, "WQL query to run" ])
      ])

  end

  def run
    host = datastore["RHOST"]

    print_status("Executing WQL")

    case action.name
    when "RAW_QUERY"
      command = datastore["WQL"]
      if datastore["NAMESPACE"].nil? or datastore["NAMESPACE"].empty?
        result = gwmi_query(command, host)
      else
        result = gwmi_query(command, host, filter=nil, namespace=datastore["NAMESPACE"])
      end
    when "OSVERSION"
      command = "SELECT * FROM win32_operatingsystem"
      filter = "Version,BuildNumber"
      result = gwmi_query(command, host, filter=filter)
    when "PROCESSINFO"
      command = "SELECT ProcessId,Name FROM Win32_Process"
      filter = "ProcessID,Name"
      result = gwmi_query(command, host, filter=filter)
    else
      print_error("Please set a valid module name")
      return false
    end

    unless result
      print_error("[#{host}] Get-WmiObject WQL query error")
      return false
    end

    print_status("WQL result: #{result}")
  end
end

