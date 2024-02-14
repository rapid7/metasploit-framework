##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MYSQL
  include Msf::OptionalSession::MySQL

  def initialize(info = {})
    super(update_info(info,
      'Name'			=> 'MySQL SQL Generic Query',
      'Description'	=> %q{
          This module allows for simple SQL statements to be executed
          against a MySQL instance given the appropriate credentials.
      },
      'Author'		=> [ 'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>' ],
      'License'		=> MSF_LICENSE,
    ))

    register_options(
      [
        OptString.new('SQL', [ true, 'The SQL to execute.',  'select version()'])
      ])
  end

  def auxiliary_commands
    { "select" => "Run a select query (a LIMIT clause is probably a really good idea)" }
  end

  def cmd_select(*args)
    datastore["SQL"] = "select #{args.join(" ")}"
    run
  end

  def run
    # If we have a session make use of it
    if session
      print_status("Using existing session #{session.sid}")
      self.mysql_conn = session.client
    else
      # otherwise fallback to attempting to login
      return unless mysql_login_datastore
    end

    print_status("Sending statement: '#{datastore['SQL']}'...")
    res = mysql_query(datastore['SQL']) || []
    res.each do |row|
      print_status(" | #{row.join(" | ")} |")
    end
  end
end
