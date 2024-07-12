##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Postgres
  include Msf::OptionalSession::PostgreSQL

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PostgreSQL Server Generic Query',
      'Description'    => %q{
          This module will allow for simple SQL statements to be executed against a
          PostgreSQL instance given the appropriate credentials.
      },
      'Author'         => [ 'todb' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://www.postgresql.org' ]
        ]
    ))
  end

  def auxiliary_commands
    { "select" => "Run a select query (a LIMIT clause is probably a really good idea)" }
  end

  def cmd_select(*args)
    datastore["SQL"] = "select #{args.join(" ")}"
    run
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def run
    self.postgres_conn = session.client if session
    ret = postgres_query(datastore['SQL'],datastore['RETURN_ROWSET'])
    case ret.keys[0]
    when :conn_error
      print_error "#{rhost}:#{rport} Postgres - Authentication failure, could not connect."
    when :sql_error
      print_error "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - #{ret[:sql_error]}"
    when :complete
      vprint_good "#{postgres_conn.peerhost}:#{postgres_conn.peerport} Postgres - Command complete."
    end
    postgres_logout if self.postgres_conn && session.blank?
  end
end
