require 'English'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT

  def initialize(info = {}) do
    super(update_info(info,
      'Name'           => 'Android Deep Link QR Code Payload Generator',
      'Description'    => %q{
        This module generates QR codes containing payload URLs for Android Deep Linking.
        When scanned, the QR code directs to a malicious Deep Linking.
      },
      'Author'         => [ 'ctkqiang' ],
      'License'        => MSF_LICENSE
    ))

    register_options([
      #  TODO
    ])

    @@list_of_deeplink = [
      "weixin://",
      "grab://",
      "boost://",
    ]

  end

  def run
    target_deep_link = ""

  end
end