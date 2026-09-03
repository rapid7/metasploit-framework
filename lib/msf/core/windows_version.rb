# -*- coding: binary -*-

module Msf
  #
  # Represents the version of a Windows operating system
  #
  class WindowsVersion

    VER_NT_WORKSTATION = 1
    VER_NT_DOMAIN_CONTROLLER = 2
    VER_NT_SERVER = 3

    module ServerSpecificVersions
      Server2003_SP0 = Rex::Version.new('5.2.3790.0')
      Server2003_SP1 = Rex::Version.new('5.2.3790.1')
      Server2003_SP2 = Rex::Version.new('5.2.3790.2')
      Server2008_SP0 = Rex::Version.new('6.0.6000.0')
      Server2008_SP1 = Rex::Version.new('6.0.6001.1')
      Server2008_SP2 = Rex::Version.new('6.0.6002.2')
      Server2008_SP2_Update = Rex::Version.new('6.0.6003.2') # https://support.microsoft.com/en-us/topic/build-number-changing-to-6003-in-windows-server-2008-1335e4d4-c155-52eb-4a45-b85bd1909ca8
      Server2008_R2_SP0 = Rex::Version.new('6.1.7600.0')
      Server2008_R2_SP1 = Rex::Version.new('6.1.7601.1')
      Server2012 = Rex::Version.new('6.2.9200.0')
      Server2012_R2 = Rex::Version.new('6.3.9600.0')
      Server2016 = Rex::Version.new('10.0.14393.0')
      Server2019 = Rex::Version.new('10.0.17763.0')
      Server2022 = Rex::Version.new('10.0.20348.0')
      Server2022_23H2 = Rex::Version.new('10.0.25398.0')
      Server2025 = Rex::Version.new('10.0.26100.0')
    end

    module WorkstationSpecificVersions
      Win2000 = Rex::Version.new('5.0.2195')
      # The actual build number is 5.0.2195.6717 but .4 suffix is consistent with other service packs in this file
      Win2000_SP4 = Rex::Version.new('5.0.2195.4')
      XP_SP0 = Rex::Version.new('5.1.2600.0')
      XP_SP1 = Rex::Version.new('5.1.2600.1')
      XP_SP2 = Rex::Version.new('5.1.2600.2')
      XP_SP3 = Rex::Version.new('5.1.2600.3')
      Vista_SP0 = Rex::Version.new('6.0.6000.0')
      Vista_SP1 = Rex::Version.new('6.0.6001.1')
      Vista_SP2 = Rex::Version.new('6.0.6002.2')
      Win7_SP0 = Rex::Version.new('6.1.7600.0')
      Win7_SP1 = Rex::Version.new('6.1.7601.1')
      Win8 = Rex::Version.new('6.2.9200.0')
      Win81 = Rex::Version.new('6.3.9600.0')
      Win10_1507 = Rex::Version.new('10.0.10240.0')
      Win10_1511 = Rex::Version.new('10.0.10586.0')
      Win10_1607 = Rex::Version.new('10.0.14393.0')
      Win10_1703 = Rex::Version.new('10.0.15063.0')
      Win10_1709 = Rex::Version.new('10.0.16299.0')
      Win10_1803 = Rex::Version.new('10.0.17134.0')
      Win10_1809 = Rex::Version.new('10.0.17763.0')
      Win10_1903 = Rex::Version.new('10.0.18362.0')
      Win10_1909 = Rex::Version.new('10.0.18363.0')
      Win10_2004 = Rex::Version.new('10.0.19041.0')
      Win10_20H2 = Rex::Version.new('10.0.19042.0')
      Win10_21H1 = Rex::Version.new('10.0.19043.0')
      Win10_21H2 = Rex::Version.new('10.0.19044.0')
      Win10_22H2 = Rex::Version.new('10.0.19045.0')
      Win11_21H2 = Rex::Version.new('10.0.22000.0')
      Win11_22H2 = Rex::Version.new('10.0.22621.0')
      Win11_23H2 = Rex::Version.new('10.0.22631.0')
      Win11_24H2 = Rex::Version.new('10.0.26100.0')
    end

    include WorkstationSpecificVersions
    include ServerSpecificVersions

    ServerNameMapping = {
      :Server2003_SP0 => "Windows Server 2003",
      :Server2003_SP1 => "Windows Server 2003 Service Pack 1",
      :Server2003_SP2 => "Windows Server 2003 Service Pack 2",
      :Server2008_SP0 => "Windows Server 2008",
      :Server2008_SP1 => "Windows Server 2008 Service Pack 1",
      :Server2008_SP2 => "Windows Server 2008 Service Pack 2",
      :Server2008_SP2_Update => "Windows Server 2008 Service Pack 2 Update",
      :Server2008_R2_SP0 => "Windows Server 2008 R2",
      :Server2008_R2_SP1 => "Windows Server 2008 R2 Service Pack 1",
      :Server2012 => "Windows Server 2012 R2",
      :Server2012_R2 => "Windows Server 2012 R2",
      :Server2016 => "Windows Server 2016",
      :Server2019 => "Windows Server 2019",
      :Server2022 => "Windows Server 2022",
      :Server2022_23H2 => "Windows Server 2022 version 23H2",
      :Server2025 => "Windows Server 2025"
    }

    WorkstationNameMapping = {
      :Win2000 => "Windows 2000",
      :Win2000_SP4 => "Windows 2000 Service Pack 4",
      :XP_SP0 => "Windows XP",
      :XP_SP1 => "Windows XP Service Pack 1",
      :XP_SP2 => "Windows XP Service Pack 2",
      :XP_SP3 => "Windows XP Service Pack 3",
      :Vista_SP0 => "Windows Vista",
      :Vista_SP1 => "Windows Vista Service Pack 1",
      :Vista_SP2 => "Windows Vista Service Pack 2",
      :Win7_SP0 => "Windows 7",
      :Win7_SP1 => "Windows 7 Service Pack 1",
      :Win8 => "Windows 8",
      :Win81 => "Windows 8.1",
      :Win10_1507 => "Windows 10 version 1507",
      :Win10_1511 => "Windows 10 version 1511",
      :Win10_1607 => "Windows 10 version 1607",
      :Win10_1703 => "Windows 10 version 1703",
      :Win10_1709 => "Windows 10 version 1709",
      :Win10_1803 => "Windows 10 version 1803",
      :Win10_1809 => "Windows 10 version 1809",
      :Win10_1903 => "Windows 10 version 1903",
      :Win10_1909 => "Windows 10 version 1909",
      :Win10_2004 => "Windows 10 version 2004",
      :Win10_20H2 => "Windows 10 version 20H2",
      :Win10_21H1 => "Windows 10 version 21H1",
      :Win10_21H2 => "Windows 10 version 21H2",
      :Win10_22H2 => "Windows 10 version 22H2",
      :Win11_21H2 => "Windows 11 version 21H2",
      :Win11_22H2 => "Windows 11 version 22H2",
      :Win11_23H2 => "Windows 11 version 23H2",
      :Win11_24H2 => "Windows 11 version 24H2"
    }

    Win10_InitialRelease = Win10_1507

    #
    # Ordered mapping used to infer a Windows version from a human-readable
    # exploit target name (see .from_target_name).
    #
    # Entries are ordered from most specific to least specific so that
    # overlapping names resolve correctly (e.g. "8.1" is claimed before "8",
    # "2008 R2" before "2008"). Each entry declares:
    #   :pattern        - regex identifying the family within the target name
    #   :base           - the oldest (baseline) version for the family, used
    #                     when no service pack is specified
    #   :service_packs  - optional map of service-pack number => version
    #
    # Year-named families (Server SKUs, Windows 2000) require the year to be
    # directly preceded by "Windows"/"Server" so that unrelated years found in
    # CVE identifiers, build numbers or product versions (e.g. "CVE-2019-1458")
    # are not mistaken for an operating system version.
    #
    TARGET_NAME_FAMILIES = [
      # --- Windows Server (always Server SKUs, must be prefixed with Windows/Server) ---
      { pattern: /(?:windows|server)\s+2025\b/i, base: ServerSpecificVersions::Server2025 },
      { pattern: /(?:windows|server)\s+2022\b/i, base: ServerSpecificVersions::Server2022 },
      { pattern: /(?:windows|server)\s+2019\b/i, base: ServerSpecificVersions::Server2019 },
      { pattern: /(?:windows|server)\s+2016\b/i, base: ServerSpecificVersions::Server2016 },
      { pattern: /(?:windows|server)\s+2012\s*r2\b/i, base: ServerSpecificVersions::Server2012_R2 },
      { pattern: /(?:windows|server)\s+2012\b/i, base: ServerSpecificVersions::Server2012 },
      {
        pattern: /(?:windows|server)\s+2008\s*r2\b/i,
        base: ServerSpecificVersions::Server2008_R2_SP0,
        service_packs: {
          0 => ServerSpecificVersions::Server2008_R2_SP0,
          1 => ServerSpecificVersions::Server2008_R2_SP1
        }
      },
      {
        pattern: /(?:windows|server)\s+2008\b/i,
        base: ServerSpecificVersions::Server2008_SP0,
        service_packs: {
          0 => ServerSpecificVersions::Server2008_SP0,
          1 => ServerSpecificVersions::Server2008_SP1,
          2 => ServerSpecificVersions::Server2008_SP2
        }
      },
      {
        pattern: /(?:windows|server)\s+2003\b/i,
        base: ServerSpecificVersions::Server2003_SP0,
        service_packs: {
          0 => ServerSpecificVersions::Server2003_SP0,
          1 => ServerSpecificVersions::Server2003_SP1,
          2 => ServerSpecificVersions::Server2003_SP2
        }
      },

      # --- Windows workstation ---
      { pattern: /\bwin(?:dows)?\s*11\b/i, base: WorkstationSpecificVersions::Win11_21H2 },
      { pattern: /\bwin(?:dows)?\s*10\b/i, base: WorkstationSpecificVersions::Win10_1507 },
      { pattern: /\bwin(?:dows)?\s*8\.1\b/i, base: WorkstationSpecificVersions::Win81 },
      { pattern: /\bwin(?:dows)?\s*8\b/i, base: WorkstationSpecificVersions::Win8 },
      {
        pattern: /\bwin(?:dows)?\s*7\b/i,
        base: WorkstationSpecificVersions::Win7_SP0,
        service_packs: {
          0 => WorkstationSpecificVersions::Win7_SP0,
          1 => WorkstationSpecificVersions::Win7_SP1
        }
      },
      {
        pattern: /\bvista\b/i,
        base: WorkstationSpecificVersions::Vista_SP0,
        service_packs: {
          0 => WorkstationSpecificVersions::Vista_SP0,
          1 => WorkstationSpecificVersions::Vista_SP1,
          2 => WorkstationSpecificVersions::Vista_SP2
        }
      },
      {
        pattern: /\bxp\b/i,
        base: WorkstationSpecificVersions::XP_SP0,
        service_packs: {
          0 => WorkstationSpecificVersions::XP_SP0,
          1 => WorkstationSpecificVersions::XP_SP1,
          2 => WorkstationSpecificVersions::XP_SP2,
          3 => WorkstationSpecificVersions::XP_SP3
        }
      },
      {
        pattern: /(?:windows|server)\s+2000\b/i,
        base: WorkstationSpecificVersions::Win2000,
        service_packs: {
          0 => WorkstationSpecificVersions::Win2000,
          1 => WorkstationSpecificVersions::Win2000,
          2 => WorkstationSpecificVersions::Win2000,
          3 => WorkstationSpecificVersions::Win2000,
          4 => WorkstationSpecificVersions::Win2000_SP4
        }
      }
    ].freeze

    module MajorRelease
      NT351 = 'Windows NT 3.51'.freeze
      Win95 = 'Windows 95'.freeze
      Win98 = 'Windows 98'.freeze
      WinME = 'Windows ME'.freeze
      Win2000 = 'Windows 2000'.freeze

      XP = 'Windows XP'.freeze
      Server2003 = 'Windows Server 2003'.freeze

      Vista = 'Windows Vista'.freeze
      Server2008 = 'Windows Server 2008'.freeze

      Win7 = 'Windows 7'.freeze
      Server2008R2 = 'Windows Server 2008 R2'.freeze

      Win8 = 'Windows 8'.freeze
      Server2012 = 'Windows Server 2012'.freeze

      Win81 = 'Windows 8.1'.freeze
      Server2012R2 = 'Windows Server 2012 R2'.freeze

      Win10Plus = 'Windows 10+'.freeze
      Server2016Plus = 'Windows Server 2016+'.freeze
    end

    def initialize(major, minor, build, service_pack, revision, product_type)
      self._major = major
      self._minor = minor
      self._build = build
      self._service_pack = service_pack
      self._revision = revision
      self.product_type = product_type
    end

    # The specific revision number of this version
    # This is mainly going to be present on Windows 10+, wherein it's easy to get it from the registry.
    def revision_number
      _revision
    end

    # The specific build number of this version (major.minor.build.service_pack)
    def build_number
      Rex::Version.new("#{_major}.#{_minor}.#{_build}.#{_service_pack}")
    end

    # Is this OS a Windows Server instance?
    def windows_server?
      # There are other types than just workstation/server/DC, but Microsoft's own documentation says
      # "If it's not Workstation, then it's Server"
      # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
      product_type != VER_NT_WORKSTATION
    end

    # Is this a Workstation build?
    def workstation?
      product_type == VER_NT_WORKSTATION
    end

    # This Windows Server has been promoted to a DC
    def domain_controller?
      product_type == VER_NT_DOMAIN_CONTROLLER
    end

    # The name of the OS, as it is most commonly rendered. Includes Service Pack if present, or build number if Win10 or higher.
    def product_name
      # First check if there's a specific, known version we have a string for
      if windows_server?
        known_version = self.class.version_string(_major, _minor, _build, ServerSpecificVersions, ServerNameMapping)
      else
        known_version = self.class.version_string(_major, _minor, _build, WorkstationSpecificVersions, WorkstationNameMapping)
      end
      return known_version unless known_version.nil?

      # Otherwise, build it up from version numbers, to the best of our ability
      result = "Unknown Windows version: #{_major}.#{_minor}.#{_build}"
      name = major_release_name
      result = name unless name.nil?
      result = "#{result} Service Pack #{_service_pack}" if _service_pack != 0
      result = "#{result} Build #{_build}" if build_number >= Win10_InitialRelease

      result
    end

    def to_s
      product_name
    end

    # Is this version number from the Vista/Server 2008 generation of Windows OSes
    def vista_or_2008?
      build_number.between?(Vista_SP0, Vista_SP2)
    end

    # Is this version number from the Windows 7/Server 2008 R2 generation of Windows OSes
    def win7_or_2008r2?
      build_number.between?(Win7_SP0, Win7_SP1)
    end

    # Is this version number from the XP/Server 2003 generation of Windows OSes
    def xp_or_2003?
      build_number.between?(XP_SP0, Server2003_SP2)
    end

    # Get the string representation of the OS, given a major, minor and build number
    # (as reported by an NTLM handshake).
    # The NTLM structure makes no guarantee that the underlying OS of the server is
    # actually Windows, so if we don't find a precise match, return nil
    #
    # @param major [Integer] The major build number reported in the NTLM handshake
    # @param minor [Integer] The minor build number reported in the NTLM handshake
    # @param build [Integer] The build build number reported in the NTLM handshake
    # @return [String] The possible matching OS versions, or nil if no corresponding match can be found
    def self.from_ntlm_os_version(major, minor, build)
      workstation_string = self.version_string(major, minor, build, WorkstationSpecificVersions, WorkstationNameMapping)
      server_string = self.version_string(major, minor, build, ServerSpecificVersions, ServerNameMapping)

      version_strings = []
      version_strings.append(workstation_string) unless workstation_string.nil?
      version_strings.append(server_string) unless server_string.nil?

      if version_strings.length > 0
        version_strings.join('/')
      else
        nil
      end
    end

    # Attempt to infer a specific Windows version from a human-readable exploit
    # target name (for example "Windows 7 SP1 x64" resolves to Win7_SP1).
    #
    # The inference is deliberately conservative so it can be relied upon for
    # automatic metadata tagging:
    #   * Only names that reference exactly one Windows family are resolved.
    #     Names referencing several different versions (e.g.
    #     "Windows XP SP3 / Windows 7 SP1") are treated as ambiguous and return
    #     nil, since no single version represents them reliably.
    #   * Generic names such as "Windows", "Windows x64" or "Windows Universal"
    #     return nil because they do not specify a version.
    #   * Year-named families (Server SKUs, Windows 2000) are only considered
    #     when the name also mentions "Windows"/"Server", so unrelated software
    #     release years are not mistaken for an OS version.
    #
    # When a family is matched without a recognisable service pack, the oldest
    # (baseline) release of that family is returned. This represents the minimum
    # Windows version the target is expected to run on, which is the value that
    # matters for payload version-compatibility checks.
    #
    # @param name [String] The exploit target name.
    # @return [Rex::Version, nil] The inferred version, or nil when the name is
    #   too generic or ambiguous to resolve reliably.
    def self.from_target_name(name)
      return nil unless name.is_a?(String) && !name.empty?

      service_packs = service_packs_from_name(name)

      matched = []
      remaining = name.dup

      TARGET_NAME_FAMILIES.each do |family|
        # Consume each occurrence so a less specific pattern (e.g. "8") cannot
        # re-match a substring already claimed by a more specific one ("8.1").
        while remaining =~ family[:pattern]
          matched << family unless matched.include?(family)
          remaining = remaining.sub(family[:pattern], ' ')
        end
      end

      # No version referenced, or the name is ambiguous (several distinct
      # versions) - not safe to tag automatically.
      return nil unless matched.length == 1

      resolve_family_version(matched.first, service_packs)
    end

    # Resolve a matched family to a concrete version, honouring any service
    # packs referenced in the name.
    #
    # @param family [Hash] An entry from TARGET_NAME_FAMILIES.
    # @param service_packs [Array<Integer>] Service-pack numbers found in the name.
    # @return [Rex::Version]
    def self.resolve_family_version(family, service_packs)
      sp_versions = family[:service_packs]
      return family[:base] if sp_versions.nil? || service_packs.empty?

      # Only consider service packs that are valid for this family. When several
      # are present (e.g. "XP SP2/SP3") pick the oldest, as it is the lowest
      # version the target could be running.
      mapped = service_packs.filter_map { |sp| sp_versions[sp] }
      mapped.min || family[:base]
    end

    # Extract every service-pack number referenced in a target name.
    #
    # @param name [String] The exploit target name.
    # @return [Array<Integer>] The unique service-pack numbers found.
    def self.service_packs_from_name(name)
      matches = name.scan(/service\s*pack\s*(\d+)/i)
      matches += name.scan(/\bsp\s?(\d+)\b/i)
      matches.flatten.map(&:to_i).uniq
    end

    private

    attr_accessor :_major, :_minor, :_build, :_service_pack, :_revision, :product_type

    # The major release within which this build fits
    def major_release_name
      if _major == 5
        if _minor == 0
          return MajorRelease::Win2000
        elsif _minor == 1
          return MajorRelease::XP
        elsif _minor == 2
          return MajorRelease::Server2003 if windows_server?

          return MajorRelease::XP # x64 Build
        end
      elsif _major == 6
        if _minor == 0
          return MajorRelease::Server2008 if windows_server?

          return MajorRelease::Vista
        elsif _minor == 1
          return MajorRelease::Server2008R2 if windows_server?

          return MajorRelease::Win7
        elsif _minor == 2
          return MajorRelease::Server2012 if windows_server?

          return MajorRelease::Win8
        elsif _minor == 3
          return MajorRelease::Server2012R2 if windows_server?

          return MajorRelease::Win81
        end
      elsif _major == 10
        if _minor == 0
          return MajorRelease::Server2016Plus if windows_server?

          return MajorRelease::Win10Plus
        end
      end
      return nil
    end

    # Get a Windows OS version string representation for a given major, minor and build number
    def self.version_string(major, minor, build, version_module, mapping)
      sorted_versions = version_module.constants
                                      .map { |version_sym| [version_sym, version_module.const_get(version_sym)] }
                                      .sort_by { |_version_sym, version| version.segments }
      sorted_versions.each do |version_sym, version|
        segments = version.segments
        if segments[0..2] == [major, minor, build]
          return mapping[version_sym]
        end
      end

      nil
    end
  end
end
