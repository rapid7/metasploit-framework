# -*- coding: binary -*-

# This module provides the SSL protocol
module Msf
  module Proto
    module SSL
      require 'msf/proto/ssl/base'
      require 'msf/proto/ssl/ccs'
      require 'msf/proto/ssl/ciphers'
      require 'msf/proto/ssl/client_hello'
      require 'msf/proto/ssl/connect'
      require 'msf/proto/ssl/datastore'
      require 'msf/proto/ssl/handshake_types'
      require 'msf/proto/ssl/record_types'
      require 'msf/proto/ssl/tls_version'
      require 'msf/proto/ssl/callbacks'
      require 'msf/proto/ssl/parsers'
      require 'msf/proto/ssl/heartbeat'

      include Msf::Proto::SSL::Callbacks

      include Msf::Exploit::Remote::Tcp

      def initialize(info = {})
        super

        register_options(
        [
          Opt::RPORT(443),
          OptEnum.new('TLS_VERSION', [true, 'TLS/SSL version to use', '1.0', ['SSLv3','1.0', '1.1', '1.2']]),
          OptEnum.new('TLS_CALLBACK', [true, 'Protocol to use, "None" to use raw TLS sockets', 'None', [ 'None', 'SMTP', 'IMAP', 'XMPP', 'POP3', 'FTP', 'POSTGRES' ]]),
          OptInt.new('RESPONSE_TIMEOUT', [true, 'Number of seconds to wait for a server response', 10])
        ], Proto::SSL)
        register_advanced_options(
        [
          OptString.new('XMPPDOMAIN', [true, 'The XMPP Domain to use when the XMPP Callback is selected', 'localhost'])
        ], Proto::SSL)
        deregister_options('RHOST')
      end
    end
  end
 end
