##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/payload/windows/reverse_http'
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD

module Metasploit4
=======
>>>>>>> rapid7/feature/complex-payloads
=======
>>>>>>> origin/feature/complex-payloads

=======
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
=======

module Metasploit4
<<<<<<< HEAD
=======
>>>>>>> feature/complex-payloads
=======
>>>>>>> 4.11.2_release_pre-rails4

=======
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
<<<<<<< HEAD
<<<<<<< HEAD
=======

module Metasploit4
>>>>>>> rapid7/master
=======

module Metasploit4
>>>>>>> rapid7/master
=======

module Metasploit4
>>>>>>> rapid7/master
=======

module Metasploit4
>>>>>>> rapid7/master

=======
<<<<<<< HEAD
<<<<<<< HEAD

module Metasploit4

>>>>>>> rapid7/master
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======

module Metasploit4

>>>>>>> rapid7/master
=======

module Metasploit4

>>>>>>> rapid7/master
=======

module Metasploit4

>>>>>>> master
=======

module Metasploit4

>>>>>>> master
=======
=======
>>>>>>> origin/pod/metasploit-api/_index.html

module Metasploit4

>>>>>>> rapid7/master
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
  CachedSize = 327

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseHttp

  def initialize(info = {})
    super(merge_info(info,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-api/_index.html
      'Name'        => 'Windows Reverse HTTP Stager (wininet)',
      'Description' => 'Tunnel communication over HTTP (Windows wininet)',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockedi http'))
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
  end

=======
=======
<<<<<<< HEAD
=======
>>>>>>> origin/payload-generator.rb
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
      'Name'          => 'Reverse HTTP Stager',
      'Description'   => 'Tunnel communication over HTTP',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseHttp,
      'Convention'    => 'sockedi http'))
  end
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/feature/complex-payloads
=======
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> feature/complex-payloads
=======
  end

>>>>>>> 4.11.2_release_pre-rails4
=======
=======
=======
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> origin/payload-generator.rb
>>>>>>> rapid7/master
=======
>>>>>>> origin/pod/metasploit-api/_index.html
      'Name'        => 'Windows Reverse HTTP Stager (wininet)',
      'Description' => 'Tunnel communication over HTTP (Windows wininet)',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockedi http'))
  end

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
>>>>>>> rapid7/master
=======
=======
>>>>>>> origin/pod/metasploit-api/_index.html
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
>>>>>>> origin/payload-generator.rb
=======
=======
>>>>>>> rapid7/master
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
end
