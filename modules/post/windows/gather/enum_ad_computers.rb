##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

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
        'Author'       => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
        'Platform'     => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'References'	=>
        [
          ['URL', 'http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx'],
        ]
      ))

    register_options([
      OptInt.new('MAX_SEARCH', [true, 'Maximum values to retrieve, 0 for all.', 50]),
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptBool.new('STORE_DB', [true, 'Store file in DB (performance hit resolving IPs).', false]),
      OptString.new('FIELDS', [true, 'FIELDS to retrieve.', 'dNSHostName,distinguishedName,description,operatingSystem,operatingSystemServicePack']),
      OptString.new('FILTER', [true, 'Search filter.', '(&(objectCategory=computer)(operatingSystem=*server*))'])
    ], self.class)
  end

  def run
    fields = datastore['FIELDS'].gsub(/\s+/,"").split(',')
    search_filter = datastore['FILTER']
    max_search = datastore['MAX_SEARCH']
    q = query(search_filter, max_search, fields)

    if q.nil? or q[:results].empty?
      return
    end

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
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
        if result[i].nil?
          field = ""
        else
          field = result[i]

          # Only perform these actions if the database is connected and we want
          # to store in the DB.
          if db and datastore['STORE_DB']
            case fields[i]
            when 'dNSHostName'
              dns = field
              report[:name] = dns
              hostnames << dns
            when 'operatingSystem'
              os = field
              index = os.index(/windows/i)
              if index
                name = 'Microsoft Windows'
                flavour = os[index..-1]
                report[:os_name] = name
                report[:os_flavor] = flavour
              else
                # Incase there are non-windows domain computers?!
                report[:os_name] = os
              end
            when 'distinguishedName'
              if field =~ /Domain Controllers/i
                report[:purpose] = "DC"
              end
            when 'operatingSystemServicePack'
              report[:os_sp] = field
            when 'description'
              report[:info] = field
            end
          end
        end

        row << field
      end

      reports << report
      results_table << row
    end

    if db and datastore['STORE_DB']
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
      print_status("Results saved to: #{stored_path}")
    end
  end

end

