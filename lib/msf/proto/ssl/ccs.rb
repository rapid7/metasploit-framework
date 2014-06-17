# -*- coding: binary -*-

# Change Cipher Spec

module Msf::Proto::SSL
  def change_cipher_spec
    payload = "\x01" # Change Cipher Spec Message
    ssl_record(RECORD_TYPE_CCS, payload)
  end
 end