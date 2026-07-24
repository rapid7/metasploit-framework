##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  include Msf::Auxiliary::Redis

  # Branch => first patched release, per the official advisory.
  # Source: https://github.com/redis/redis/security/advisories/GHSA-4789-qfc9-5f9q
  PATCHED_VERSIONS = {
    [6, 2] => '6.2.20',
    [7, 2] => '7.2.11',
    [7, 4] => '7.4.6',
    [8, 0] => '8.0.4',
    [8, 2] => '8.2.2'
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Redis Lua Use-After-Free Version Scanner (RediShell / CVE-2025-49844)',
        'Description' => %q{
          This module fingerprints a remote Redis (or Redis-protocol compatible service,
          such as Valkey) and determines whether it is running a version affected by
          CVE-2025-49844, publicly referred to as "RediShell" -- a critical use-after-free
          vulnerability in Redis's Lua scripting garbage collector that can allow an
          authenticated user to achieve remote code execution.

          This module is detection-only. It does not attempt to trigger the use-after-free
          condition, manipulate the garbage collector, or execute arbitrary code of any
          kind. It reports the Redis version, compares it against the officially patched
          release for that branch, and (optionally) sends a harmless "EVAL return 1 0"
          probe purely to confirm whether Lua scripting is reachable at all, since a
          target with EVAL/EVALSHA blocked via ACL is at meaningfully lower real-world
          risk even on an unpatched version.
        },
        'Author' => [
          'Can Ünüvar X-croot'
        ],
        'References' => [
          ['CVE', '2025-49844'],
          ['GHSA', '4789-qfc9-5f9q'],
          ['URL', 'https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844'],
          ['URL', 'https://redis.io/blog/security-advisory-cve-2025-49844/']
        ],
        'DisclosureDate' => '2025-10-03',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptBool.new('CHECK_LUA', [true, 'Send a harmless EVAL probe to confirm Lua scripting is reachable', true])
      ]
    )
  end

  def run_host(_ip)
    connect

    info_response = redis_command('INFO', 'server')
    unless info_response
      vprint_error("#{peer} - No response to INFO command")
      return
    end

    unless /redis_version:(?<redis_version>\S+)/ =~ info_response
      vprint_error("#{peer} - Could not find redis_version in INFO response")
      return
    end

    report_redis(redis_version)

    parsed = parse_redis_version(redis_version)
    unless parsed
      vprint_error("#{peer} - Unparseable Redis version string: #{redis_version}")
      return
    end

    status = redis_patch_status(parsed)
    lua_status = lua_probe

    case status
    when :vulnerable
      case lua_status
      when :reachable
        print_good("#{peer} - Redis #{redis_version}: VULNERABLE to CVE-2025-49844 (RediShell) - unpatched branch and Lua EVAL is reachable")
      when :blocked
        print_warning("#{peer} - Redis #{redis_version}: unpatched branch for CVE-2025-49844, but EVAL/EVALSHA look blocked (ACL?) - real-world risk reduced")
      else
        print_warning("#{peer} - Redis #{redis_version}: unpatched branch for CVE-2025-49844; could not confirm whether Lua scripting is reachable")
      end
    when :patched
      print_status("#{peer} - Redis #{redis_version}: patched against CVE-2025-49844")
    when :unknown
      print_status("#{peer} - Redis #{redis_version}: patch status for CVE-2025-49844 could not be determined automatically for this branch - verify manually against the advisory")
    end
  ensure
    disconnect
  end

  private

  def parse_redis_version(str)
    match = /\A(\d+)\.(\d+)\.(\d+)/.match(str)
    return nil unless match

    {
      major: match[1].to_i,
      minor: match[2].to_i,
      full: Rex::Version.new("#{match[1]}.#{match[2]}.#{match[3]}")
    }
  end

  def redis_patch_status(parsed)
    branch = [parsed[:major], parsed[:minor]]
    fixed_in = PATCHED_VERSIONS[branch]

    return parsed[:full] >= Rex::Version.new(fixed_in) ? :patched : :vulnerable if fixed_in

    if branch[0] < 6 || branch == [6, 0] || branch == [6, 1]
      # Pre-6.2 branches are EOL and were not part of the official backport list; Lua
      # scripting has existed since 2.6, so treat these as vulnerable rather than unknown.
      :vulnerable
    else
      # A branch newer than any covered by the advisory at the time this module was
      # written (or an otherwise unrecognized branch/fork) - don't guess, flag for
      # manual review instead.
      :unknown
    end
  end

  def lua_probe
    return :skipped unless datastore['CHECK_LUA']

    response = redis_command('EVAL', 'return 1', '0')
    return :unknown if response.nil?

    if response.include?(':1')
      :reachable
    elsif response =~ /\A-/ || response =~ /unknown command|NOSCRIPT|not allowed|NOPERM|NOAUTH/i
      :blocked
    else
      :unknown
    end
  end
end
