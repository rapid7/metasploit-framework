# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/payload/uuid'

module Msf

###
#
# Basic send_uuid stub for PHP payloads
#
###

module Payload::Php::SendUUID

  #
  # Generate PHP code that writes the UUID to the socket.
  #
  def php_send_uuid(opts={})
    sock_var = opts[:sock_var] || '$s'
    sock_type = opts[:sock_type] || '$s_type'

    uuid = opts[:uuid] || generate_payload_uuid
    uuid_raw = uuid.to_raw.chars.map { |c| '\x%.2x' % c.ord }.join('')

    php = %Q^$u="#{uuid_raw}";
switch (#{sock_type}) { 
case 'stream': fwrite(#{sock_var}, $u); break;
case 'socket': socket_write(#{sock_var}, $u); break;
}
^
    php
  end

end

end

