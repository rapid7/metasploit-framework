##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MYSQL

  def initialize(info = {})
    super(update_info(info,
      'Name'			=> 'MySQL SQL Generic Query',
      'Description'	=> %q{
          This module allows for simple SQL statements to be executed
          against a MySQL instance given the appropriate credentials.
      },
      'Author'		=> [ 'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>' ],
      'License'		=> MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('SQL', [ true, 'The SQL to execute.',  'select version()'])
      ], self.class)
  end

  def auxiliary_commands
    { "select" => "Run a select query (a LIMIT clause is probably a really good idea)" }
  end

  def cmd_select(*args)
    datastore["SQL"] = "select #{args.join(" ")}"
    run
  end

  def run
    return if not mysql_login_datastore
    print_status("Sending statement: '#{datastore['SQL']}'...")
    res = mysql_query(datastore['SQL']) || []
    res.each do |row|
      print_status(" | #{row.join(" | ")} |")
    end
  end

end
