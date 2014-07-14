# -*- coding: binary -*-

module Msf::Proto::SSL::Callbacks
  require 'msf/proto/ssl/callbacks/ftp'
  require 'msf/proto/ssl/callbacks/imap'
  require 'msf/proto/ssl/callbacks/pop3'
  require 'msf/proto/ssl/callbacks/postgres'
  require 'msf/proto/ssl/callbacks/smtp'
  require 'msf/proto/ssl/callbacks/xmpp'

  TLS_CALLBACKS = {
    'SMTP'      => :tls_smtp,
    'IMAP'      => :tls_imap,
    'XMPP'      => :tls_xmpp,
    'POP3'      => :tls_pop3,
    'FTP'       => :tls_ftp,
    'POSTGRES'  => :tls_postgres
  }
end
