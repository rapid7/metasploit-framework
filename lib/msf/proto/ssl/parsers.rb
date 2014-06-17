# -*- coding: binary -*-

module Msf::Proto::SSL
  require 'msf/proto/ssl/parsers/certificates'
  require 'msf/proto/ssl/parsers/handshakes'
  require 'msf/proto/ssl/parsers/server_hello'
  require 'msf/proto/ssl/parsers/ssl_record'

  include Msf::Proto::SSL::Parsers
end
