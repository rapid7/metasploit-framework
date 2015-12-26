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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD

module Metasploit4
=======
>>>>>>> rapid7/feature/complex-payloads
=======
>>>>>>> origin/feature/complex-payloads
=======

module Metasploit4
<<<<<<< HEAD
=======
>>>>>>> feature/complex-payloads
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3

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
=======
<<<<<<< HEAD
<<<<<<< HEAD

module Metasploit4
<<<<<<< HEAD
=======
>>>>>>> feature/complex-payloads
=======
>>>>>>> 4.11.2_release_pre-rails4

=======
<<<<<<< HEAD
=======
>>>>>>> msf-complex-payloads
=======
=======
<<<<<<< HEAD
>>>>>>> pod/metasploit-gemfile-
=======
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-serialized_class_loader
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> payload-generator.rb
=======
>>>>>>> pod/metasploit-gemfile-
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-framework
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
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
<<<<<<< HEAD
<<<<<<< HEAD

=======
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> pod/metasploit-gemfile-

=======
>>>>>>> origin/pod/metasploit-framework
=======

=======
>>>>>>> origin/pod/metasploit-serialized_class_loader

module Metasploit4

>>>>>>> rapid7/master
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> msf-complex-payloads
=======

=======

=======
>>>>>>> origin/pod/metasploit-framework
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
=======

module Metasploit4

>>>>>>> rapid7/master
=======

module Metasploit4

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> master
>>>>>>> pod/metasploit-gemfile-
=======
>>>>>>> master
>>>>>>> origin/pod/metasploit-serialized_class_loader
=======

module Metasploit4

<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/master
=======
=======
>>>>>>> pod/complex-payloads
=======
>>>>>>> master
=======
>>>>>>> pod/metasploit-gemfile-

module Metasploit4

>>>>>>> origin/pod/metasploit-framework
>>>>>>> rapid7/master
=======

module Metasploit4

>>>>>>> master
=======

module Metasploit4

>>>>>>> master
<<<<<<< HEAD
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
=======
<<<<<<< HEAD
>>>>>>> payload-generator.rb
=======
>>>>>>> pod/metasploit-gemfile-
=======
>>>>>>> master
=======

module Metasploit4

>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-serialized_class_loader
=======

module Metasploit4

<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/master
<<<<<<< HEAD
>>>>>>> msf-complex-payloads
=======
=======
>>>>>>> master
>>>>>>> pod/metasploit-gemfile-
=======
>>>>>>> master
>>>>>>> origin/pod/metasploit-serialized_class_loader
=======

module Metasploit4

>>>>>>> master
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> payload-generator.rb
=======
>>>>>>> pod/metasploit-gemfile-
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
=======

module Metasploit4

<<<<<<< HEAD
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> master
>>>>>>> origin/pod/metasploit-serialized_class_loader
=======

module Metasploit4

<<<<<<< HEAD
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> master
>>>>>>> origin/pod/metasploit-serialized_class_loader
=======

module Metasploit4

<<<<<<< HEAD
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
>>>>>>> origin/pod/metasploit-framework
=======
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-serialized_class_loader
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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-api/_index.html
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-framework
      'Name'        => 'Windows Reverse HTTP Stager (wininet)',
      'Description' => 'Tunnel communication over HTTP (Windows wininet)',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockedi http'))
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-framework
  end

=======
=======
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/payload-generator.rb
=======
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> msf-complex-payloads
=======
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> msf-complex-payloads
=======
>>>>>>> origin/pod/metasploit-framework
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
<<<<<<< HEAD
>>>>>>> payload-generator.rb
>>>>>>> origin/pod/metasploit-framework
=======
<<<<<<< HEAD
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
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> pod/metasploit-gemfile-
>>>>>>> origin/pod/metasploit-framework
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-serialized_class_loader
      'Name'          => 'Reverse HTTP Stager',
      'Description'   => 'Tunnel communication over HTTP',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseHttp,
      'Convention'    => 'sockedi http'))
<<<<<<< HEAD
<<<<<<< HEAD
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
<<<<<<< HEAD
<<<<<<< HEAD
  end
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> feature/complex-payloads
=======
  end

>>>>>>> 4.11.2_release_pre-rails4
=======
=======
>>>>>>> msf-complex-payloads
=======
=======
=======
=======
  end
>>>>>>> pod/metasploit-gemfile-
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-framework
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
=======
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
=======
>>>>>>> master
<<<<<<< HEAD
=======
=======
>>>>>>> origin/pod/metasploit-framework
>>>>>>> master
=======
>>>>>>> master
=======
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
>>>>>>> rapid7/master
=======
>>>>>>> origin/pod/metasploit-api/_index.html
=======
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
>>>>>>> master
>>>>>>> pod/metasploit-gemfile-
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
      'Name'        => 'Windows Reverse HTTP Stager (wininet)',
      'Description' => 'Tunnel communication over HTTP (Windows wininet)',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockedi http'))
  end

=======
  end
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
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
>>>>>>> origin/pod/metasploit-serialized_class_loader
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> payload-generator.rb
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> pod/metasploit-gemfile-
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
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
>>>>>>> origin/pod/metasploit-framework
      'Name'        => 'Windows Reverse HTTP Stager (wininet)',
      'Description' => 'Tunnel communication over HTTP (Windows wininet)',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockedi http'))
<<<<<<< HEAD
<<<<<<< HEAD
  end

<<<<<<< HEAD
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
=======
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
<<<<<<< HEAD
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
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
>>>>>>> master
=======
>>>>>>> master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
=======
=======
>>>>>>> rapid7/master
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
=======
      'Name'          => 'Reverse HTTP Stager',
      'Description'   => 'Tunnel communication over HTTP',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseHttp,
      'Convention'    => 'sockedi http'))
  end
>>>>>>> feature/complex-payloads
=======
  end

>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
=======
>>>>>>> pod/complex-payloads
  end

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/master
=======
>>>>>>> payload-generator.rb
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
<<<<<<< HEAD
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
>>>>>>> msf-complex-payloads
=======
>>>>>>> msf-complex-payloads
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
=======
>>>>>>> master
=======
>>>>>>> master
=======
<<<<<<< HEAD
>>>>>>> rapid7/master
>>>>>>> pod/metasploit-gemfile-
=======
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
>>>>>>> master
=======
>>>>>>> master
=======
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/master
=======
>>>>>>> master
>>>>>>> payload-generator.rb
=======
>>>>>>> master
=======
>>>>>>> master
>>>>>>> pod/metasploit-gemfile-
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
>>>>>>> origin/pod/metasploit-framework
=======
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-serialized_class_loader
end
