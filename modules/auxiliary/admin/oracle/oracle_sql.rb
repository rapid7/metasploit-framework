##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle SQL Generic Query',
      'Description'    => %q{
          This module allows for simple SQL statements to be executed
          against a Oracle instance given the appropriate credentials
          and sid.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://www.metasploit.com/users/mc' ],
        ],
      'DisclosureDate' => 'Dec 7 2007'))

      register_options(
        [
          OptString.new('SQL', [ false, 'The SQL to execute.',  'select * from v$version']),
        ], self.class)
  end

  def run
    return if not check_dependencies

    query = datastore['SQL']

    begin
      print_status("Sending statement: '#{query}'...")
      result = prepare_exec(query)
      #Need this if 'cause some statements won't return anything
      if result
        result.each do |line|
          print_status(line)
        end
      end
    rescue => e
      return
    end
  end

end
