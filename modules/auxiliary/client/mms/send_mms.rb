##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Mms

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MMS Client',
      'Description'    => %q{
        This module sends an MMS message to multiple phones of the same carrier.
        You can use it to send a malicious attachment to phones.
      },
      'Author'         => [ 'sinn3r' ],
      'License'        => MSF_LICENSE
    ))
  end

  def run
    phone_numbers = datastore['CELLNUMBERS'].split
    print_status("Sending mms message to #{phone_numbers.length} number(s)...")
    begin
      res = send_mms(phone_numbers, datastore['MMSSUBJECT'], datastore['TEXTMESSAGE'], datastore['MMSFILE'], datastore['MMSFILECTYPE'])
      print_status("Done.")
    rescue Rex::Proto::Mms::Exception => e
      print_error(e.message)
    end
  end
end
