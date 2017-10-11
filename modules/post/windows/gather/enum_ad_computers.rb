##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info={})
    super( update_info( info,
        'Name'	       => 'Windows Gather Active Directory Computers',
        'Description'  => %Q{
            This module will enumerate computers in the default AD directory.

            Optional Attributes to use in ATTRIBS:
            objectClass, cn, description, distinguishedName, instanceType, whenCreated,
            whenChanged, uSNCreated, uSNChanged, name, objectGUID,
            userAccountControl, badPwdCount, codePage, countryCode,
            badPasswordTime, lastLogoff, lastLogon, localPolicyFlags,
            pwdLastSet, primaryGroupID, objectSid, accountExpires,
            logonCount, sAMAccountName, sAMAccountType, operatingSystem,
            operatingSystemVersion, operatingSystemServicePack, serverReferenceBL,
            dNSHostName, rIDSetPreferences, servicePrincipalName, objectCategory,
            netbootSCPBL, isCriticalSystemObject, frsComputerReferenceBL,
            lastLogonTimestamp, msDS-SupportedEncryptionTypes

            ActiveDirectory has a MAX_SEARCH limit of 1000 by default. Split search up
            if you hit that limit.

            Possible filters:
            (objectClass=computer) # All Computers
            (primaryGroupID=516)  # All Domain Controllers
            (&(objectCategory=computer)(operatingSystem=*server*)) # All Servers
        },
        'License'      => MSF_LICENSE,
        'Author'       => [ 'Ben Campbell' ],
        'Platform'     => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'References'	=>
        [
          ['URL', 'http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx'],
        ]
      ))

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptBool.new('STORE_DB', [true, 'Store file in DB (performance hit resolving IPs).', false]),
      OptString.new('FIELDS', [true, 'FIELDS to retrieve.', 'dNSHostName,distinguishedName,description,operatingSystem,operatingSystemServicePack']),
      OptString.new('FILTER', [true, 'Search filter.', '(&(objectCategory=computer)(operatingSystem=*server*))'])
    ])
  end

  def run
    fields = datastore['FIELDS'].gsub(/\s+/,"").split(',')
    search_filter = datastore['FILTER']
    max_search = datastore['MAX_SEARCH']

    begin
      q = query(search_filter, max_search, fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error(e.message)
      return
    end

    return if q.nil? or q[:results].empty?

    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
      'Header'     => "Domain Computers",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => fields
    )

    # Hostnames holds DNS Names to Resolve
    hostnames = []
    # Reports are collections for easy database insertion
    reports = []
    q[:results].each do |result|
      row = []

      report = {}
      0.upto(fields.length-1) do |i|
        field = result[i][:value] || ""

        # Only perform these actions if the database is connected and we want
        # to store in the DB.
        if db && datastore['STORE_DB']
          case fields[i]
          when 'dNSHostName'
            dns = field
            report[:name] = dns
            hostnames << dns
          when 'operatingSystem'
            report[:os_name] = field.gsub("\xAE",'')
          when 'distinguishedName'
            if field =~ /Domain Controllers/i
              # TODO: Find another way to mark a host as being a domain controller
              #       The 'purpose' field should be server, client, device, printer, etc
              #report[:purpose] = "DC"
              report[:purpose] = "server"
            end
          when 'operatingSystemServicePack'
            # XXX: Does this take into account the leading 'SP' string?

            if field.to_i > 0
              report[:os_sp] = 'SP' + field
            end
            if field =~ /(Service Pack|SP)\s?(\d+)/
              report[:os_sp] = 'SP' + $2
            end

          when 'description'
            report[:info] = field
          end
        end

        row << field
      end

      reports << report
      results_table << row
    end

    if db && datastore['STORE_DB']
      print_status("Resolving IP addresses...")
      ip_results = client.net.resolve.resolve_hosts(hostnames, AF_INET)

      # Merge resolved array with reports
      reports.each do |report|
        ip_results.each do |ip_result|
          if ip_result[:hostname] == report[:name]
            report[:host] = ip_result[:ip]
            vprint_good("Database report: #{report.inspect}")
            report_host(report)
          end
        end
      end
    end

    print_line results_table.to_s
    if datastore['STORE_LOOT']
      stored_path = store_loot('ad.computers', 'text/plain', session, results_table.to_csv)
      print_good("Results saved to: #{stored_path}")
    end
  end
end

