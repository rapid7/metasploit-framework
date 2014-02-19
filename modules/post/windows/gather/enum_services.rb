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
        This module will query the system for services and display name and
        configuration info for each returned service. It allows you to
        optionally search the credentials, path, or start type for a string
        and only return the results that match. These query operations are
        cumulative and if no query strings are specified, it just returns all
        services.  NOTE: If the script hangs, windows firewall is most likely
        on and you did not migrate to a safe process (explorer.exe for
        example).
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

    qcred = datastore["CRED"]
    qpath = datastore["PATH"]

    if qcred
      qcred = qcred.downcase
      print_status("Credential Filter: " + qcred)
    end

    if qpath
      qpath = qpath.downcase
      print_status("Executable Path Filter: " + qpath)
    end

    if datastore["TYPE"] == "All"
      qtype = nil
    else
      qtype = datastore["TYPE"].downcase
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

      # make sure we got a service name
      if srv[:name]
        begin
          srv_conf = service_info(srv[:name])
          if srv_conf[:startname]
            # filter service based on filters passed, the are cumulative
            if qcred && !srv_conf[:startname].downcase.include?(qcred)
              next
            end

            if qpath && !srv_conf[:path].downcase.include?(qpath)
              next
            end

            # There may not be a 'Startup', need to check nil
            if qtype && !(START_TYPE[srv_conf[:starttype]] || '').downcase.include?(qtype)
              next
            end

            results_table << [srv[:name],
                              srv_conf[:startname],
                              START_TYPE[srv_conf[:starttype]],
                              srv_conf[:path]]
          end

        rescue RuntimeError => e
          print_error("An error occurred enumerating service: #{srv[:name]}: #{e}")
        end
      else
        print_error("Problem enumerating services")
      end
    end

    print_line results_table.to_s
  end

end
