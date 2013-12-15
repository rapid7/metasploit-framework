##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Services

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Gather Service Info Enumeration",
      'Description'          => %q{
        This module will query the system for services and display name and configuration
        info for each returned service. It allows you to optionally search the credentials, path, or start
        type for a string and only return the results that match. These query operations
        are cumulative and if no query strings are specified, it just returns all services.
        NOTE: If the script hangs, windows firewall is most likely on and you did not
        migrate to a safe process (explorer.exe for example).
        },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['Keith Faber', 'Kx499']
    ))
    register_options(
      [
        OptString.new('CRED', [ false, 'String to search credentials for' ]),
        OptString.new('PATH', [ false, 'String to search path for' ]),
        OptEnum.new('TYPE', [false, 'Service startup Option', 'All', ['All', 'Auto', 'Manual', 'Disabled' ]])
      ], self.class)
  end


  def run

    # set vars
    qcred = datastore["CRED"] || nil
    qpath = datastore["PATH"] || nil
    if datastore["TYPE"] == "All"
      qtype = nil
    else
      qtype = datastore["TYPE"]
    end
    if qcred
      print_status("Credential Filter: " + qcred)
    end
    if qpath
      print_status("Executable Path Filter: " + qpath)
    end
    if qtype
      print_status("Start Type Filter: " + qtype)
    end

    results_table = Rex::Ui::Text::Table.new(
        'Header'     => 'Services',
        'Indent'     => 1,
        'SortIndex'  => 0,
        'Columns'    => ['Name', 'Credentials', 'Command', 'Startup']
    )

    print_status("Listing Service Info for matching services:")
    service_list.each do |srv|
      srv_conf = {}

      #make sure we got a service name
      if srv[:name]
        begin
          srv_conf = service_info(srv[:name])
          #filter service based on filters passed, the are cumulative
          if qcred and ! srv_conf['Credentials'].downcase.include? qcred.downcase
            next
          end

          if qpath and ! srv_conf['Command'].downcase.include? qpath.downcase
            next
          end

          # There may not be a 'Startup', need to check nil
          if qtype and ! (srv_conf['Startup'] || '').downcase.include? qtype.downcase
            next
          end

          results_table << [srv[:name], srv_conf['Credentials'], srv_conf['Startup'], srv_conf['Command']]

        rescue
          print_error("An error occured enumerating service: #{srv[:name]}")
        end
      else
        print_error("Problem enumerating services")
      end
    end

    print_line results_table.to_s
  end

end
