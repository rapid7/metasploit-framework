#
# Leverage the Recog gem as much as possible for sane fingerprint management
#
require 'recog'

#
# Rules for operating system fingerprinting in Metasploit
#
# The `os.product` key identifies the common-name of a specific operating system
# Examples include: Linux, Windows XP, Mac OS X, IOS, AIX, HP-UX, VxWorks
#
# The `os.version` key identifies the service pack or version of the operating system
# Sometimes this means a kernel or firmware version when the distribution or OS
# version is not available.
# Examples include: SP2, 10.04, 2.6.47, 10.6.1
#
# The `os.vendor` key identifies the manufacturer of the operating system
# Examples include: Microsoft, Ubuntu, Cisco, HP, IBM, Wind River
#
# The `os.family` key identifies the group of the operating system. This is often a
# duplicate of os.product, unless a more specific product name is available.
# Examples include: Windows, Linux, IOS, HP-UX, AIX
#
# The `os.edition` key identifies the specific variant of the operating system
# Examples include: Enterprise, Professional, Starter, Evaluation, Home, Datacenter
#
# An example breakdown of a common operating system is shown below
#
#  * Microsoft Windows XP Professional Service Pack 3 English (x86)
#     - os.product  = 'Windows XP'
#     - os.edition  = 'Professional'
#     - os.vendor   = 'Microsoft'
#     - os.version  = 'SP3'
#     - os.language = 'English'
#     - os.arch     = 'x86'
#
# These rules are then mapped to the {Mdm::Host} attributes below:
#
#   * os_name     - Maps to a normalized os.product key
#   * os_flavor   - Maps to a normalized os.edition key
#   * os_sp       - Maps to a normalized os.version key (soon os_version)
#   * os_lang     - Maps to a normalized os.language key
#   * arch        - Maps to a normalized os.arch key
#
# Additional rules include the following mappings:
#
#   * name        - Maps to the host.name key
#   * mac         - Maps to the host.mac key
#
# The following keys are not mapped to {Mdm::Host} at this time (but should be):
#
#   * os.vendor
#
# In order to execute these rules, this module is responsible for mapping various
# fingerprint sources to {Mdm::Host} values. This requires some ugly glue code to
# account for differences between each supported input (external scanners), the
# Recog gem and associated databases, and how Metasploit itself likes to handle
# these values. Getting a mapping wrong is often harmless, but can impact the
# automatic targetting capabilities of certain exploit modules.
#
# In other words, this is a best-effort attempt to rationalize multiple competing
# sources of information about a host and come up with the values representing a
# normalized assessment of the system. The use of `Recog` and multiple scanner
# fingerprints can result in a comprehensive (and confident) identification of the
# remote operating system and associated services.
#
# Historically, there are direct conflicts between certain Metasploit modules,
# certain scanners, and external fingerprint databases in terms of how a
# particular OS and patch level is represented. This module attempts to fix what
# it can and serve as documentation and live workarounds for the rest.
#
# Examples of known conflicts that are still in progress:
#
# * Metasploit defines an OS constant of 'win'/'windows' as Microsoft Windows
#
#   - Scanner modules report a mix of 'Microsoft Windows' and 'Windows'
#   - Nearly all exploit modules reference 'Windows <Release> SP<Version>'
#   - Nmap (and other scanners) also prefix the vendor before Windows
#
#
# * Windows service packs represented as 'Service Pack X' or 'SPX'
#
#   - The preferred form is to set os.version to 'SPX'
#   - Many external scanners & Recog prefer 'Service Pack X'
#
# * Apple Mac OS X, Cisco IOS, IBM AIX, Ubuntu Linux, all reported with vendor prefix
#
#   - The preferred form is to remove the vendor from os.product
#   - {Mdm::Host} currently has no vendor field, so this information is lost today
#   - Many scanners report leading vendor strings and require normalization
#
#  * The os_flavor field is used in contradictory ways across Metasploit
#
#   - The preferred form is to be a 'display only' field
#   - Some Recog fingerprints still append the edition to os.product
#   - Many scanners report the edition as a trailing suffix to os.product
#
#
#
#
# Maintenance:
#
# 1. Ensure that the latest Recog gem is present and installed
# 2. For new operating system releases, update relevant sections
#    a) Windows releases will require updates to a few methods
#      1) parse_windows_os_str()
#      2) normalize_nmap_fingerprint()
#      3) normalize_nexpose_fingerprint()
#      4) Other scanner normalizers
#    b) Mobile operating systems are minimally recognized
#
#
# @todo Handle OS icon incompatiblities with new fingerprint names
#       Note that VMWare ESX(i) was special cased before as well, make sure it still works
#       1) Cisco IOS -> IOS breaks the icon mapping in MSP/MSCE of /cisco/
#       2) Ubuntu Linux -> Linux breaks the distro selection
#       The real solution is to add os_vendor and take this into account for icons
#
# @todo Implement rspec coverage for normalize_os()
# @todo Implement smb.generic fingerprint database (replace {#parse_windows_os_str}?)
# @todo Implement Samba version matching for specific distributions and OS versions
# @todo Implement DD-WRT and various embedded device signatures currently missing
# @todo Correct inconsistencies in os_name use by removing the vendor string (Microsoft Windows -> Windows)
#       This applies to MSF core and a handful of modules, not to mention some Recog fingerprints.
# @todo Rename host.os_sp to host.os_version
# @todo Add host.os_vendor
# @todo Add host.os_confidence
# @todo Add host.domain
#
module Mdm::Host::OperatingSystemNormalization

  # Cap nmap certainty at 0.84 until we update it more frequently
  # XXX: Without this, Nmap will beat the default certainty of recog
  #      matches and its less-confident guesses will take precedence
  #      over service-based fingerprints.
  MAX_NMAP_CERTAINTY = 0.84

  #
  # Normalize the operating system fingerprints provided by various scanners
  # (nmap, nexpose, retina, nessus, metasploit modules, and more!)
  #
  # These are stored as {Mdm::Note notes} (instead of directly in the os_*
  # fields) specifically for this purpose.
  #
  # The goal is to infer as much as we can about the OS of the device and the
  # various {Mdm::Service services} offered using the Recog gem and some glue
  # logic to determine the best weights. This method can result in changes to
  # the recorded {#os_name}, {#os_flavor}, {#os_sp}, {#os_lang}, {#purpose},
  # {#name}, {#arch}, and the {Mdm::Service service details}.
  #
  def normalize_os
    host   = self
    matches = []

    # Note that we're already restricting the query to this host by using
    # host.notes instead of Note, so don't need a host_id in the
    # conditions.
    fingerprintable_notes = self.notes.where("ntype like '%%fingerprint'")
    fingerprintable_notes.each do |fp_note|
      matches += recog_matches_for_note(fp_note)
    end

    # XXX: This hack solves the memory leak generated by self.services.each {}
    fingerprintable_services = self.services.where("name is not null and name != '' and info is not null and info != ''")
    fingerprintable_services.each do |s|
      matches += recog_matches_for_service(s)
    end

    #
    # Look for generic fingerprint.match notes that generate a match hash from modules
    # This handles ad-hoc os.language, host.name, etc identifications
    #
    generated_matches = self.notes.where(ntype: 'fingerprint.match')
    generated_matches.each do |m|
      next unless (m.data and m.data.kind_of?(::Hash))
      matches << m.data.dup
    end

    # Normalize matches for consistency during the ranking phase
    matches = matches.map{ |m| normalize_match(m) }

    # Calculate the best OS match based on fingerprint hits
    match = Recog::Nizer.best_os_match(matches)

    # Merge and normalize the best match to the host object
    apply_match_to_host(match) if match

    # Set some sane defaults if needed
    host.os_name ||= 'Unknown'
    host.purpose ||= 'device'

    host.save if host.changed?
  end

  # Recog matches for the `s` service.
  #
  # @param s [Mdm::Service]
  # @return [Array<Hash>] Keys will be host, service, and os attributes
  def recog_matches_for_service(s)
    #
    # We assume that the service.info field contains certain types of probe
    # replies and associate these with one or more Recog databases. The mapping
    # of service.name to a specific database only fits into so many places and
    # Mdm currently serves that role.
    #

    service_match_keys = {
      # TODO: Implement smb.generic fingerprint database
      # 'smb'     => [ 'smb.generic' ], # Distinct from smb.fingerprint, use os.certainty to choose best match
      # 'netbios' => [ 'smb.generic' ], # Distinct from smb.fingerprint, use os.certainty to choose best match

      'ssh'     => [ 'ssh.banner' ], # Recog expects just the vendor string, not the protocol version
      'http'    => [ 'http_header.server', 'apache_os'], # The 'Apache' fingerprints try to infer OS/distribution from the extra information in the Server header
      'https'   => [ 'http_header.server', 'apache_os'], # XXX: verify vmware esx(i) case on https (TODO: normalize https to http, track SSL elsewhere, such as a new set of fields)
      'snmp'    => [ 'snmp.sys_description' ],
      'telnet'  => [ 'telnet.banner' ],
      'smtp'    => [ 'smtp.banner' ],
      'imap'    => [ 'imap4.banner' ],  # Metasploit reports 143/993 as imap (TODO: normalize imap to imap4)
      'pop3'    => [ 'pop3.banner' ],   # Metasploit reports 110/995 as pop3
      'nntp'    => [ 'nntp.banner' ],
      'ftp'     => [ 'ftp.banner' ],
      'ssdp'    => [ 'ssdp_header.server' ]
    }

    matches = []

    return matches unless service_match_keys.has_key?(s.name)

    service_match_keys[s.name].each do |rdb|
      banner = s.info
      if self.respond_to?("service_banner_recog_filter_#{s.name}")
        banner = self.send("service_banner_recog_filter_#{s.name}", banner)
      end
      res = Recog::Nizer.match(rdb, banner)
      matches << res if res
    end

    matches
  end

  # Recog matches for the fingerprint in `note`.
  #
  # @return [Array<Hash>] Keys will be host, service, and os attributes
  def recog_matches_for_note(note)
    # Skip notes that are missing the correct structure or have been blacklisted
    return [] if not validate_fingerprint_data(note)

    #
    # These rules define the relationship between fingerprint note keys
    # and specific Recog databases for detailed matching. Notes that do
    # not match a rule are passed to the generic matcher.
    #
    fingerprint_note_match_keys = {
      'smb.fingerprint'  => {
        :native_os               => [ 'smb.native_os' ],
      },
      'http.fingerprint' => {
        :header_server           => [ 'http_header.server', 'apache_os' ],
        :header_set_cookie       => [ 'http_header.cookie' ],
        :header_www_authenticate => [ 'http_header.wwwauth' ],
      # TODO: Candidates for future Recog support
      # :content                 => 'http_body'
      # :code                    => 'http_response_code'
      # :message                 => 'http_response_message'
      }
    }

    matches = []

    # Look for a specific Recog database for this type and data key
    if fingerprint_note_match_keys.has_key?( note.ntype )
      fingerprint_note_match_keys[ note.ntype ].each_pair do |k,rdbs|
        if note.data.has_key?(k)
          rdbs.each do |rdb|
            res = Recog::Nizer.match(rdb, note.data[k])
            matches << res if res
          end
        end
      end
    else
      # Add all generic match results to the overall match array
      normalize_scanner_fp(note).each do |m|
        next unless m
        matches << m
      end
    end

    matches
  end

  # Determine if the fingerprint data is readable. If not, it nearly always
  # means that there was a problem with the YAML or the Marshal'ed data,
  # so let's log that for later investigation.
  def validate_fingerprint_data(fp)
    if fp.data.kind_of?(Hash) and !fp.data.empty?
      return true
    elsif fp.ntype == "postgresql.fingerprint"
      # Special case postgresql.fingerprint; it's always a string,
      # and should not be used for OS fingerprinting (yet), so
      # don't bother logging it. TODO: fix os fingerprint finding, this
      # name collision seems silly.
      return false
    else
      return false
    end
  end

  #
  # Normalize matches in order to handle inconsistencies between fingerprint
  # sources and our desired usage in Metasploit. This amounts to yet more
  # duct tape, but the situation should improve as the fingerprint sources
  # are updated and enhanced. In the future, this method will no longer
  # be needed (or at least, doing less and less work)
  #
  def normalize_match(m)
    # Normalize os.version strings containing 'Service Pack X' to just 'SPX'
    if m['os.version'] and m['os.version'].index('Service Pack ') == 0
      m['os.version'] = m['os.version'].gsub(/Service Pack /, 'SP')
    end

    if m['os.product']

      # Normalize Apple Mac OS X to just Mac OS X
      if m['os.product'] =~ /^Apple Mac/
        m['os.product']  = m['os.product'].gsub(/Apple Mac/, 'Mac')
        m['os.vendor'] ||= 'Apple'
      end

      # Normalize Sun Solaris/Sun SunOS to just Solaris/SunOS
      if m['os.product'] =~ /^Sun (Solaris|SunOS)/
        m['os.product']  = m['os.product'].gsub(/^Sun /, '')
        m['os.vendor'] ||= 'Oracle'
      end

      # Normalize Microsoft Windows to just Windows to catch any stragglers
      if m['os.product'] =~ /^Microsoft Windows/
        m['os.product']  = m['os.product'].gsub(/Microsoft Windows/, 'Windows')
        m['os.vendor'] ||= 'Microsoft'
      end

      # Normalize Windows Server to just Windows to match Metasploit target names
      if m['os.product'] =~ /^Windows Server/
        m['os.product'] = m['os.product'].gsub(/Windows Server/, 'Windows')
      end

      # Normalize OS Family
      m = normalize_match_family(m)
    end

    m
  end

  # Normalize matches in order to ensure that an os.family entry exists
  # if we have enough data to put one together.
  def normalize_match_family(m)
    # If the os.family already exists, we don't need to do anything
    return m if m['os.family'].present?
    case m['os.product']
      when /Windows/
        m['os.family'] = 'Windows'
      when /Linux/
        m['os.family'] = 'Linux'
      when /Solaris/
        m['os.family'] = 'Solaris'
      when /SunOS/
        m['os.family'] = 'SunOS'
      when /AIX/
        m['os.family'] = 'AIX'
      when /HP-UX/
        m['os.family'] = 'HP-UX'
      when /OS X/
        m['os.family'] = 'OS X'
    end
    m
  end

  #
  # Recog assumes that the protocol version of the SSH banner has been removed
  #
  def service_banner_recog_filter_ssh(banner)
    if banner =~ /^SSH-\d+\.\d+-(.*)/
      $1
    else
      banner
    end
  end

  #
  # Examine the assertations of the merged best match and map these
  # back to fields of {Mdm::Host}. Take particular care not to leave
  # related fields (os_*) in a conflicting state, leverage existing
  # values where possible, and use the most confident values we have.
  #
  def apply_match_to_host(match)
    host = self

    # These values in a match always override the current value unless
    # the host attribute has been explicitly locked by the user

    if match['host.mac'] && !host.attribute_locked?(:mac)
      host.mac = sanitize(match['host.mac'])
    end

    if match['host.name'] && !host.attribute_locked?(:name)
      host.name = sanitize(match['host.name'])
    end

    # Select the os architecture if available
    if match['os.arch'] && !host.attribute_locked?(:arch)
      host.arch = sanitize(match['os.arch'])
    end

    # Guess the purpose using some basic heuristics
    if ! host.attribute_locked?(:purpose)
      host.purpose = guess_purpose_from_match(match)
    end

    #
    # Map match fields from Recog fingerprint style to Metasploit style
    #

    # os.build:                 Examples: 9001, 2600, 7602
    # os.device:                Examples: General, ADSL Modem, Broadband router, Cable Modem, Camera, Copier, CSU/DSU
    # os.edition:               Examples: Web, Storage, HPC, MultiPoint, Enterprise, Home, Starter, Professional
    # os.family:                Examples: Windows, Linux, Solaris, NetWare, ProCurve, Mac OS X, HP-UX, AIX
    # os.product:               Examples: Windows, Linux, Windows Server 2008 R2, Windows XP, Enterprise Linux, NEO Tape Library
    # os.vendor:                Examples: Microsoft, HP, IBM, Sun, 3Com, Ricoh, Novell, Ubuntu, Apple, Cisco, Xerox
    # os.version:               Examples: SP1, SP2, 6.5 SP3 CPR, 10.04, 8.04, 12.10, 4.0, 6.1, 8.5
    # os.language:              Examples: English, Arabic, German
    # linux.kernel.version:     Examples: 2.6.32

    # Metasploit currently ignores os.build, os.device, and os.vendor as separate fields.

    # Select the OS name from os.name, fall back to os.family
    if ! host.attribute_locked?(:os_name)
      # Try to fill this value from os.product first if it exists
      if match.has_key?('os.product')
        host.os_name = sanitize(match['os.product'])
      else
        # Fall back to os.family otherwise, if available
        if match.has_key?('os.family')
          host.os_name = sanitize(match['os.family'])
        end
      end
    end

    if match.has_key?('os.family')
      host.os_family = sanitize(match['os.family'])
    end

    # Select the flavor from os.edition if available
    if match.has_key?('os.edition') and ! host.attribute_locked?(:os_flavor)
      host.os_flavor = sanitize(match['os.edition'])
    end

    # Select an OS version as os.version, fall back to linux.kernel.version
    if ! host.attribute_locked?(:os_sp)
      if match['os.version']
        host.os_sp = sanitize(match['os.version'])
      else
        if match['linux.kernel.version']
          host.os_sp = sanitize(match['linux.kernel.version'])
        end
      end
    end

    # Select the os language if available
    if match.has_key?('os.language') and ! host.attribute_locked?(:os_lang)
      host.os_lang = sanitize(match['os.language'])
    end

    # Normalize MAC addresses to lower-case colon-delimited format
    if host.mac and ! host.attribute_locked?(:mac)
      host.mac = host.mac.downcase
      if host.mac =~ /^[a-f0-9]{12}$/
        host.mac = host.mac.scan(/../).join(':')
      end
    end
  end

  #
  # Loosely guess the purpose of a device based on available
  # match values. In the future, also take into account the
  # exposed services and rename to guess_purpose_with_match()
  #
  def guess_purpose_from_match(match)
    # some data that is sent to this is numeric; we do not want that
    pstr = ""
    # Go through each character of each value and make sure it is all
    # UTF-8
    match.values.each do |i|
      if i.respond_to?(:encoding)
        i.each_char do |j|
          begin
            pstr << j.downcase.encode("UTF-8")
          rescue Encoding::UndefinedConversionError
          # rescue Encoding::UndefinedConversionError => e
            # this works in Framework, but causes a Travis CI error
            # elog("Found incompatible (non-ANSI) character in guess_purpose_from_match")
          end
        end
      end
    end
    # Loosely map keywords to specific purposes
    case pstr
    when /windows server|windows (nt|20)/
      'server'
    when /windows (xp|vista|[78]|10)/
      'client'
    when /printer|print server/
      'printer'
    when /router/
      'router'
    when /firewall/
      'firewall'
    when /linux/
      'server'
    else
      'device'
    end
  end

  # Ensure that the host attribute is using ascii safe text
  # and escapes any other byte value.
  def sanitize(text)
    Rex::Text.ascii_safe_hex(text)
  end

  #
  # Normalize data from Meterpreter's client.sys.config.sysinfo()
  #
  def normalize_session_fingerprint(data)
    ret = {}
    case data[:os]
      when /Windows/
        ret.update(parse_windows_os_str(data[:os]))
    # Switch to this code block once the multi-meterpreter code review is complete
=begin

      when /^(Windows \w+)\s*\(Build (\d+)(.*)\)/
        ret['os.product'] = $1
        ret['os.build'] = $2
        ret['os.vendor'] = 'Microsoft'
        possible_sp = $3
        if possible_sp =~ /Service Pack (\d+)/
          ret['os.version'] = 'SP' + $1
        end
=end
      when /Linux (\d+\.\d+\.\d+\S*)\s* \((\w*)\)/
        ret['os.product'] = "Linux"
        ret['os.version'] = $1
        ret['os.arch']    = get_arch_from_string($2)
      else
        ret['os.product'] = data[:os]
    end
    ret['os.arch'] = data[:arch] if data[:arch]
    ret['host.name'] = data[:name] if data[:name]
    [ ret ]
  end

  #
  # Normalize data from Nmap fingerprints
  #
  def normalize_nmap_fingerprint(data)
    ret = {}

    # :os_vendor=>"Microsoft" :os_family=>"Windows" :os_version=>"2000" :os_accuracy=>"94"
    ret['os.certainty'] = ( data[:os_accuracy].to_f / 100.0 ).to_s if data[:os_accuracy]
    if (data[:os_vendor] == data[:os_family])
      ret['os.product'] = data[:os_family]
    else
      ret['os.product'] = data[:os_family]
      ret['os.vendor'] = data[:os_vendor]
    end

    # Nmap places the type of Windows (XP, 7, etc) into the version field
    if ret['os.product'] == 'Windows' and data[:os_version]
      ret['os.product'] = ret['os.product'] + ' ' + data[:os_version].to_s
    else
      ret['os.version'] = data[:os_version]
    end

    ret['host.name'] = data[:hostname] if data[:hostname]

    if ret['os.certainty']
      ret['os.certainty'] = [ ret['os.certainty'].to_f, MAX_NMAP_CERTAINTY ].min.to_s
    end

    [ ret ]
  end

  #
  # Normalize data from MBSA fingerprints
  #
  def normalize_mbsa_fingerprint(data)
    ret = {}
    # :os_match=>"Microsoft Windows Vista SP0 or SP1, Server 2008, or Windows 7 Ultimate (build 7000)"
    #    :os_vendor=>"Microsoft" :os_family=>"Windows" :os_version=>"7" :os_accuracy=>"100"
    ret['os.certainty'] = ( data[:os_accuracy].to_f / 100.0 ).to_s if data[:os_accuracy]
    ret['os.family']    = data[:os_family] if data[:os_family]
    ret['os.vendor']    = data[:os_vendor] if data[:os_vendor]

    if data[:os_family] and data[:os_version]
      ret['os.product'] = data[:os_family] + " " + data[:os_version]
    end

    ret['host.name'] = data[:hostname] if data[:hostname]

    [ ret ]
  end


  #
  # Normalize data from Nexpose fingerprints
  #
  def normalize_nexpose_fingerprint(data)
    ret = {}
    # :family=>"Windows" :certainty=>"0.85" :vendor=>"Microsoft" :product=>"Windows 7 Ultimate Edition"
    # :family=>"Windows" :certainty=>"0.67" :vendor=>"Microsoft" :arch=>"x86" :product=>'Windows 7' :version=>'SP1'
    # :family=>"Linux" :certainty=>"0.64" :vendor=>"Linux" :product=>"Linux"
    # :family=>"Linux" :certainty=>"0.80" :vendor=>"Ubuntu" :product=>"Linux"
    # :family=>"IOS" :certainty=>"0.80" :vendor=>"Cisco" :product=>"IOS"
    # :family=>"embedded" :certainty=>"0.61" :vendor=>"Linksys" :product=>"embedded"

    ret['os.certainty'] = data[:certainty] if data[:certainty]
    ret['os.family']    = data[:family]    if data[:family]
    ret['os.vendor']    = data[:vendor]    if data[:vendor]

    case data[:product]
    when /^Windows/

      # TODO: Verify Windows CE and Windows 8 RT fingerprints
      # Translate the version into the representation we want

      case data[:version].to_s

      # These variants are normalized to just 'Windows <Version>'
      when "NT", "2000", "95", "ME", "XP", "Vista", "7", "8", "8.1"
        ret['os.product'] = "Windows #{data[:version]}"

      # Service pack in the version field should be recognized
      when /^SP\d+/, /^Service Pack \d+/
        ret['os.product'] = data[:product]
        ret['os.version'] = data[:version]

      # No version means the version is part of the product already
      when nil, ''
        # Trim any 'Server' suffix and use as it is
        ret['os.product'] = data[:product].sub(/ Server$/, '')

      # Otherwise, we assume a Server version of Windows
      else
        ret['os.product'] = "Windows Server #{data[:version]}"
      end

      # Extract the edition string if it is present
      if data[:product] =~ /(XP|Vista|\d+(?:\.\d+)) (\w+|\w+ \w+|\w+ \w+ \w+) Edition/
        ret['os.edition'] = $2
      end

    when nil, 'embedded'
      # Use the family or vendor name when the product is empty or 'embedded'
      ret['os.product']   = data[:family] unless data[:family] == 'embedded'
      ret['os.product'] ||= data[:vendor]
      ret['os.version']   = data[:version] if data[:version]
    else
      # Default to using the product name reported by Nexpose
      ret['os.product'] = data[:product] if data[:product]
    end

    ret['os.arch'] = get_arch_from_string(data[:arch]) if data[:arch]
    ret['os.arch'] ||= get_arch_from_string(data[:desc]) if data[:desc]

    [ ret ]
  end


  #
  # Normalize data from Retina fingerprints
  #
  def normalize_retina_fingerprint(data)
    ret = {}
    # :os=>"Windows Server 2003 (X64), Service Pack 2"
    case data[:os]
      when /Windows/
        ret.update(parse_windows_os_str(data[:os]))
      else
        # No idea what this looks like if it isn't windows.  Just store
        # the whole thing and hope for the best.
        # TODO: Add examples of non-Windows results
        ret['os.product'] = data[:os] if data[:os]
    end
    [ ret ]
  end


  #
  # Normalize data from Nessus fingerprints
  #
  def normalize_nessus_fingerprint(data)
    ret = {}
    # :os=>"Microsoft Windows 2000 Advanced Server (English)"
    # :os=>"Microsoft Windows 2000\nMicrosoft Windows XP"
    # :os=>"Linux Kernel 2.6"
    # :os=>"Sun Solaris 8"
    # :os=>"IRIX 6.5"

    # Nessus sometimes jams multiple OS names together with a newline.
    oses = data[:os].split(/\n/)
    if oses.length > 1
      # Multiple fingerprints means Nessus wasn't really sure, reduce
      # the certainty accordingly
      ret['os.certainty'] = 0.5
    else
      ret['os.certainty'] = 0.8
    end

    # Since there is no confidence associated with them, the best we
    # can do is just take the first one.
    case oses.first
      when /^(Microsoft |)Windows/
        ret.update(parse_windows_os_str(data[:os]))

      when /(2\.[46]\.\d+[-a-zA-Z0-9]+)/
        # Look for older Linux kernel versions
        ret['os.product'] = "Linux"
        ret['os.version'] = $1

      when /^Linux Kernel ([\d\.]+)(.*)/
        # Look for strings like "Linux Kernel 2.6 on Ubuntu 9.10 (karmic)"
        # Ex: Linux Kernel 2.2 on Red Hat Linux release 6.2 (Zoot)
        # Ex: Linux Kernel 2.6 on Ubuntu Linux 8.04 (hardy)
        ret['os.product'] = "Linux"
        ret['os.version'] = $1

        vendor = $2.to_s

        # Try to snag the vendor name as well
        if vendor =~ /on (\w+|\w+ \w+|\w+ \w+ \w+) (Linux|\d)/
          ret['os.vendor'] = $1
        end

      when /(.*) ([0-9\.]+)$/
        # Then we don't necessarily know what the os is, but this fingerprint has
        # some version information at the end, pull it off, treat the first part
        # as the OS, and the rest as the version.
        ret['os.product'] = $1.gsub("Kernel", '').strip
        ret['os.version'] = $2
      else
        # TODO: Return each OS guess as a separate match
        ret['os.product'] = oses.first
    end

    ret['host.name'] = data[:hname] if data[:hname]
    [ ret ]
  end

  #
  # Normalize data from Qualys fingerprints
  #
  def normalize_qualys_fingerprint(data)
    ret = {}
    # :os=>"Microsoft Windows 2000"
    # :os=>"Windows 2003"
    # :os=>"Microsoft Windows XP Professional SP3"
    # :os=>"Ubuntu Linux"
    # :os=>"Cisco IOS 12.0(3)T3"
    # :os=>"Red-Hat Linux 6.0"
    case data[:os]
      when /Windows/
        ret.update(parse_windows_os_str(data[:os]))

      when /^(Cisco) (IOS) (\d+[^\s]+)/
        ret['os.product'] = $2
        ret['os.vendor']  = $1
        ret['os.version'] = $3

      when /^([^\s]+) (Linux)(.*)/
        ret['os.product'] = $2
        ret['os.vendor'] = $1

        ver = $3.to_s.strip.split(/\s+/).first
        if ver =~ /^\d+\./
          ret['os.version'] = ver
        end

      else
        parts = data[:os].split(/\s+/, 3)
        ret['os.product'] = "Unknown"
        ret['os.product'] = parts[0] if parts[0]
        ret['os.product'] << " " + parts[1] if parts[1]
        ret['os.version'] = parts[2] if parts[2]
    end
    [ ret ]
  end

  #
  # Normalize data from FusionVM fingerprints
  #
  def normalize_fusionvm_fingerprint(data)
    ret = {}
    case data[:os]
      when /Windows/
        ret.update(parse_windows_os_str(data[:os]))
      when /Linux ([^[:space:]]*) ([^[:space:]]*) .* (\(.*\))/
        ret['os.product'] = "Linux"
        ret['host.name']  = $1
        ret['os.version'] = $2
        ret['os.arch']    = get_arch_from_string($3)
      else
        ret['os.product'] = data[:os]
    end
    ret['os.arch'] = data[:arch] if data[:arch]
    ret['host.name'] = data[:name] if data[:name]
    [ ret ]
  end

  #
  # Normalize data from generic fingerprints
  #
  def normalize_generic_fingerprint(data)
    ret = {}
    ret['os.product'] = data[:os_name] || data[:os] || data[:os_fingerprint] || "Unknown"
    ret['os.arch'] = data[:os_arch] if data[:os_arch]
    ret['os.certainty'] = data[:os_certainty] || 0.5
    [ ret ]
  end

  #
  # Convert a host.os.*_fingerprint Note into a hash containing 'os.*' and 'host.*' fields
  #
  # Also includes a os.certainty which is a float from 0 - 1.00 indicating the
  # scanner's confidence in its fingerprint.  If the particular scanner does
  # not provide such information, default to 0.80.
  #
  def normalize_scanner_fp(fp)
    hits = []

    return hits if not validate_fingerprint_data(fp)

    case fp.ntype
    when /^host\.os\.(.*_fingerprint)$/
      pname = $1
      pmeth = 'normalize_' + pname
      if self.respond_to?(pmeth)
        hits = self.send(pmeth, fp.data)
      else
        hits = normalize_generic_fingerprint(fp.data)
      end
    end
    hits.each {|hit| hit['os.certainty'] ||= 0.80}
    hits
  end

  #
  # Take a windows version string and return a hash with fields suitable for
  # Host this object's version fields. This is used as a fall-back to parse
  # external fingerprints and should eventually be replaced by per-source
  # mappings.
  #
  # A few example strings that this will have to parse:
  # sessions
  #   Windows XP (Build 2600, Service Pack 3).
  #   Windows .NET Server (Build 3790).
  #   Windows 2008 (Build 6001, Service Pack 1).
  # retina
  #   Windows Server 2003 (X64), Service Pack 2
  # nessus
  #   Microsoft Windows 2000 Advanced Server (English)
  # qualys
  #   Microsoft Windows XP Professional SP3
  #   Windows 2003
  #
  # Note that this list doesn't include nexpose or nmap, since they are
  # both kind enough to give us the various strings in seperate pieces
  # that we don't have to parse out manually.
  #
  def parse_windows_os_str(str)
    ret = {}

    # Set some reasonable defaults for Windows
    ret['os.vendor']  = 'Microsoft'
    ret['os.product'] = 'Windows'

    # Determine the actual Windows product name
    case str
      when /\.NET Server/
        ret['os.product'] << ' Server 2003'
      when / (2000|2003|2008|2012)/
        ret['os.product'] << ' Server ' + $1
      when / (NT (?:3\.51|4\.0))/
        ret['os.product'] << ' ' + $1
      when /Windows (95|98|ME|XP|Vista|[\d\.]+)/
        ret['os.product'] << ' ' + $1
      else
        # If we couldn't pull out anything specific for the flavor, just cut
        # off the stuff we know for sure isn't it and hope for the best
        ret['os.product'] = (ret['os.product'] + ' ' + str.gsub(/(Microsoft )|(Windows )|(Service Pack|SP) ?(\d+)/i, '').strip).strip

        # Make sure the product name doesn't include any non-alphanumeric stuff
        # This fixes cases where the above code leaves 'Windows XX (Build 3333,)...'
        ret['os.product'] = ret['os.product'].split(/[^a-zA-Z0-9 ]/).first.strip

    end

    # Take a guess at the architecture
    arch = get_arch_from_string(str)
    ret['os.arch'] = arch if arch

    # Extract any service pack value in the string
    if str =~ /(Service Pack|SP) ?(\d+)/i
      ret['os.version']  = "SP#{$2}"
    end

    # Extract any build ID found in the string
    if str =~ /build (\d+)/i
      ret['os.build'] = $1
    end

    # Extract the OS edition if available
    if str =~ /(\d+|\d+\.\d+) (\w+|\w+ \w+|\w+ \w+ \w+) Edition/
      ret['os.edition'] = $2
    else
      if str =~ /(Professional|Enterprise|Pro|Home|Start|Datacenter|Web|Storage|MultiPoint)/
        ret['os.edition'] = $1
      end
    end

    ret
  end

  #
  # Return a normalized architecture based on patterns in the input string.
  # This will identify things like sparc, powerpc, x86_x64, and i686
  #
  def get_arch_from_string(str)
    res = Recog::Nizer.match("architecture", str)
    return unless (res and res['os.arch'])
    res['os.arch']
  end
end
