##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanUniqueQuery
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'			=> 'SQLMAP SQL Injection External Module',
      'Description'	=> %q{
          This module launch a sqlmap session.
        sqlmap is an automatic SQL injection tool developed in Python.
        Its goal is to detect and take advantage of SQL injection
        vulnerabilities on web applications. Once it detects one
        or more SQL injections on the target host, the user can
        choose among a variety of options to perform an extensive
        back-end database management system fingerprint, retrieve
        DBMS session user and database, enumerate users, password
        hashes, privileges, databases, dump entire or user
        specific DBMS tables/columns, run his own SQL SELECT
        statement, read specific files on the file system and much
        more.
      },
      'Author'	    => [ 'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>' ],
      'License'		=> BSD_LICENSE,
      'References'	=>
        [
          ['URL', 'http://sqlmap.sourceforge.net'],
        ]
      ))

    register_options(
      [
        OptPath.new('SQLMAP_PATH', [ true,  "The sqlmap >= 0.6.1 full path ", '/sqlmap' ]),
        OptEnum.new('METHOD', [true, 'HTTP Method', 'GET', ['GET', 'POST']]),
        OptString.new('PATH', [ true,  "The path/file to test for SQL injection", 'index.php' ]),
        OptString.new('QUERY', [ false, "HTTP GET query", 'id=1' ]),
        OptString.new('DATA', [ false, "The data string to be sent through POST" ]),
        OptString.new('OPTS', [ false,  "The sqlmap options to use" ]),
        OptBool.new('BATCH', [ true,  "Never ask for user input, use the default behaviour", true ])
      ], self.class)
  end

  # Modify to true if you have sqlmap installed.
  def wmap_enabled
    false
  end

  # Test a single host
  def run_host(ip)

    sqlmap = File.join(datastore['SQLMAP_PATH'], 'sqlmap.py')
    if not File.file?(sqlmap)
      print_error("The sqlmap script could not be found")
      return
    end

    data = ""
    data << datastore['DATA'].to_s
    opts = datastore['OPTS']
    method = datastore['METHOD'].upcase

    wmap_target_host = datastore['VHOST'] if datastore['VHOST']

    sqlmap_url  = (datastore['SSL'] ? "https" : "http")
    sqlmap_url << "://"
    sqlmap_url << wmap_target_host
    sqlmap_url << ":"
    sqlmap_url << wmap_target_port
    sqlmap_url << "/"
    sqlmap_url << datastore['PATH']

    if method == "GET"
      sqlmap_url << '?'
      sqlmap_url << datastore['QUERY']
    elsif method == "POST"
      data << "&"
      data << datastore['QUERY']
    end

    cmd = [ sqlmap ]
    cmd += [ '-u', sqlmap_url ]
    if opts
      cmd << opts
    end
    if data
      cmd += [ '--data', data ]
    end
    if datastore['BATCH'] == true
      cmd << '--batch'
    end

    print_status("exec: #{cmd.inspect}")
    system(*cmd)
  end

end
