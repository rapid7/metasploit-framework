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
          query can be used by defining the MODULE option. The following MODULEs are
          available: OSVERSION - Returns information about the operating system,
          PROCESSINFO - Returns running processes.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Chris Higgins' ], # msf module - @ch1gg1ns
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptString.new("MODULE" , [ false, "Module query to run", "OSVERSION" ]),
        OptString.new("NAMESPACE" , [ false, "Namespace to run the WQL query against" ]),
        OptString.new("WQL" , [ false, "WQL query to run" ])
      ])

  end

  def run
    if datastore["MODULE"].present? && datastore["WQL"].present?
      print_error("Cannot set both MODULE and WQL, only one")
      return false
    end

    host = datastore["RHOST"]

    print_status("Executing WQL")

    if datastore["MODULE"].nil? or datastore["MODULE"].empty?
      command = datastore["WQL"]
      if datastore["NAMESPACE"].nil? or datastore["NAMESPACE"].empty?
        result = gwmi_query(command, host)
      else
        result = gwmi_query(command, host, filter=nil, namespace=datastore["NAMESPACE"])
      end
    else
      case datastore["MODULE"]
      when "OSVERSION"
        command = "SELECT * FROM win32_operatingsystem"
        filter = "Version,BuildNumber"
      when "PROCESSINFO"
        command = "SELECT ProcessId,Name FROM Win32_Process"
        filter = "ProcessID,Name"
      else
        print_error("Please set a valid module name")
        return false
      end
        result = gwmi_query(command, host, filter=filter)
    end

    unless result
      print_error("[#{host}] Get-WmiObject WQL query error")
      return false
    end

    print_status("WQL result: #{result}")
  end
end

