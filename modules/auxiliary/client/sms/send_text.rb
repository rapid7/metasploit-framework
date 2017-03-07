##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Sms

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SMS Client',
      'Description'    => %q{
        This module sends a text message to multiple phones of the same carrier.
        You can use it to send a malicious link to phones.

        Please note that you do not use this module to send a media file (attachment),
        because that is MMS.
      },
      'Author'         => [ 'sinn3r' ],
      'License'        => MSF_LICENSE
    ))
  end

  def run
    phone_numbers = datastore['CELLNUMBERS'].split
    print_status("Sending text (#{datastore['SMSMESSAGE'].length} bytes) to #{phone_numbers.length} number(s)...")
    begin
      res = send_text(phone_numbers, datastore['SMSMESSAGE'])
      print_status("Done.")
    rescue Rex::Proto::Sms::Exception => e
      print_error(e.message)
    end
  end

end
