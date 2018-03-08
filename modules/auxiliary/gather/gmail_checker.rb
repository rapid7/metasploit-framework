##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Check e-mail valid by gmail',
      'Description' => %q{
      This module check valid e-mail by gmail},
      'Author' => [ 'Mateus Lino <dctoralves@protonmail.ch>' ],
      'License' => MSF_LICENSE))

    register_options([
        OptString.new('CHEK_GMAIL', [true, 'check emails valid by gmail']),
     ])
end

  def check_gmail(targetdom)
  print_status(". . . CHECKING . . . ")
  clnt = URI("https://mail.google.com/mail/gxlu?email=#{targetdom}@gmail.com")
  resp = Net::HTTP.get_response(clnt)
  if resp['Set-Cookie']  || resp.get_cookies
  print_status("E-mail valid")
  else
  print_status("E-mail invalid")
  end
 end
def run
    print_status("Checking email")
    target = datastore['CHEK_GMAIL']
    check_gmail(target) if datastore['CHEK_GMAIL']
   end
end


