##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# bluehammer_defender_audit — DEFENSIVE post module for CVE-2026-33825 "BlueHammer".
#
# Read-only detection / hunting / audit ONLY. This module does NOT exploit the
# TOCTOU flaw, does NOT touch the SAM database, and does NOT modify Defender
# configuration. It answers three questions on an already-compromised host during
# an authorized assessment: is Defender vulnerable, is it exposed in practice, and
# is there evidence the host was targeted by the BlueHammer exploit.
#
class MetasploitModule < Msf::Post
  include Msf::Post::Common

  # Patched Defender Antimalware Platform build (14 Apr 2026). See research/detection-baseline.md.
  DEFAULT_FIXED_VERSION = '4.18.26030.3011'.freeze
  DEFENDER_SIGNATURE = 'DfndrPEBluHmr'.freeze
  DEFENDER_OP_LOG = 'Microsoft-Windows-Windows Defender/Operational'.freeze
  # Signatures older than this (days) count as stale posture. See research/detection-baseline.md sec.3.
  SIG_STALE_DAYS = 7

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Defender BlueHammer (CVE-2026-33825) Compromise Audit',
        'Description' => %q{
          Defensive, read-only audit for CVE-2026-33825 ("BlueHammer"), a patched
          TOCTOU flaw (CWE-1220) in Microsoft Defender that allowed a low-privileged
          user to read the SAM database. This module performs NO exploitation. On an
          authorized post-exploitation session it reports three things:
          (A) whether the Defender platform build is below the fixed version
          (4.18.26030.3011), cross-checking PowerShell, the on-disk platform folder,
          and the platform binary version; (B) whether posture (Tamper Protection,
          real-time protection, shadow copies, signature currency) would leave the
          host exposed in practice; and (C) whether the Windows Defender Operational
          log or known Huntress IOCs show evidence the host was targeted by the
          exploit (detected as Exploit:Win32/DfndrPEBluHmr.BZ). Output is a scored
          verdict, a vulnerability/note report, and an optional JSON loot snapshot.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Anas Abo Ghaddara' ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'References' => [
          [ 'CVE', '2026-33825' ],
          [ 'CWE', '1220' ],
          [ 'URL', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33825' ],
          [ 'URL', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' ],
          [ 'URL', 'https://www.huntress.com/blog/nightmare-eclipse-intrusion' ]
        ],
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [],
          'SideEffects' => [] # read-only: no config changes, no exploitation
        }
      )
    )

    register_options([
      OptString.new('FIXED_VERSION', [ true, 'Patched Defender platform baseline', DEFAULT_FIXED_VERSION ]),
      OptBool.new('HUNT_LOG', [ true, 'Hunt the Defender Operational log for targeting evidence', true ]),
      OptInt.new('HUNT_DAYS', [ true, 'Lookback window (days) for the log hunt', 90 ]),
      OptPath.new('IOC_FILE', [ false, 'Local iocs.json to load path/hash IOCs from', '' ]),
      OptBool.new('STORE_LOOT', [ true, 'Store a JSON audit snapshot as loot', true ])
    ])
  end

  def run
    print_status('BlueHammer (CVE-2026-33825) defensive audit — read-only, no exploitation.')
    unless defender_present?
      print_error('Microsoft Defender not detected on this host; nothing to audit.')
      return
    end

    version = check_version   # (A) Phase 3
    posture = check_posture   # (B) Phase 4
    targeting = hunt_targeting # (C) Phase 5 — collection_script decides what is gathered (log vs IOC scan)

    verdict = score(version, posture, targeting)
    report(verdict, version, posture, targeting)
  end

  #
  # ---- Host collection: one read-only PowerShell pass, memoized ------------
  #
  def collected
    @collected ||= begin
      raw = run_ps(collection_script)
      json = raw.to_s[/\{.*\}/m]
      json ? JSON.parse(json) : {}
    rescue JSON::ParserError => e
      print_error("Could not parse host data: #{e.message}")
      {}
    end
  end

  # Execute a PowerShell script on the target via -EncodedCommand and return stdout.
  # Every cmdlet used by collection_script is read-only; nothing on the host changes.
  def run_ps(script)
    enc = Rex::Text.encode_base64(Rex::Text.to_unicode(script))
    # Explicit, generous timeout: collection can read the event log and hash files,
    # which may exceed cmd_exec's 15s default on busy hosts. Truncated output would
    # otherwise fail to parse and be misread as "Defender not detected".
    cmd_exec("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand #{enc}", nil, 180)
  end

  def collection_script
    tpl = <<~'PS'
      $ErrorActionPreference='SilentlyContinue'
      $o=[ordered]@{}
      $o.present=[bool](Get-Service WinDefend)
      $mp=Get-MpComputerStatus
      $o.ps_version=$mp.AMProductVersion
      $o.tamper=$mp.IsTamperProtected
      $o.rtp=$mp.RealTimeProtectionEnabled
      $o.behavior=$mp.BehaviorMonitorEnabled
      $o.onaccess=$mp.OnAccessProtectionEnabled
      $o.sig_version=$mp.AntivirusSignatureVersion
      $o.sig_age_days=if($mp.AntivirusSignatureLastUpdated){[int]((Get-Date)-$mp.AntivirusSignatureLastUpdated).TotalDays}else{$null}
      $plat=Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform" -Directory | Sort-Object Name -Descending | Select-Object -First 1
      $o.dir_version=if($plat){$plat.Name}else{$null}
      $mpcmd=if($plat){Join-Path $plat.FullName 'MpCmdRun.exe'}else{$null}
      $o.file_version=if($mpcmd -and (Test-Path $mpcmd)){(Get-Item $mpcmd).VersionInfo.ProductVersion}else{$null}
      $o.shadow_count=@(Get-CimInstance Win32_ShadowCopy).Count
      $o.detections=@()
      $o.staged=@()
      if (__HUNT_LOG__) {
        $since=(Get-Date).AddDays(-__DAYS__)
        $events=@(Get-WinEvent -FilterHashtable @{LogName='__LOG__';Id=1116,1117;StartTime=$since} -MaxEvents 500)
        $o.detections=@($events | ForEach-Object { $tn=''; try { $x=[xml]$_.ToXml(); $tn=[string](($x.Event.EventData.Data | Where-Object { $_.Name -eq 'Threat Name' }).'#text') } catch {}; [ordered]@{ time=$_.TimeCreated.ToString('o'); id=$_.Id; threat=$tn; msg=(($_.Message -split "`n")[0]).Trim() } })
      }
      if (__SCAN_FILES__) {
        $dirs=@()
        Get-ChildItem 'C:\Users' -Directory | ForEach-Object { $dirs+=(Join-Path $_.FullName 'Downloads'); $dirs+=(Join-Path $_.FullName 'Pictures') }
        $files=@()
        foreach($d in $dirs){ if(Test-Path $d){ Get-ChildItem $d -Recurse -Include *.exe -File | Select-Object -First 300 | ForEach-Object { $h=if(__HASH__){(Get-FileHash -Algorithm SHA256 $_.FullName).Hash}else{$null}; $files+=[ordered]@{ path=$_.FullName; sha256=$h } } } }
        $o.staged=$files
      }
      $o | ConvertTo-Json -Depth 5 -Compress
    PS
    tpl.gsub('__DAYS__', datastore['HUNT_DAYS'].to_i.to_s)
       .gsub('__LOG__', DEFENDER_OP_LOG)
       .gsub('__HUNT_LOG__', datastore['HUNT_LOG'] ? '$true' : '$false')
       .gsub('__SCAN_FILES__', scan_files? ? '$true' : '$false')
       .gsub('__HASH__', hash_iocs? ? '$true' : '$false')
  end

  #
  # ---- Guard --------------------------------------------------------------
  #
  def defender_present?
    collected['present'] == true || !collected['ps_version'].to_s.empty?
  end

  #
  # ---- (A) Vulnerable? ----------------------------------------------------
  #
  def check_version
    c = collected
    raw = { powershell: c['ps_version'], platform_dir: c['dir_version'], file: c['file_version'] }
          .reject { |_, v| v.to_s.empty? }
    # Normalize to the dotted numeric core so a folder-suffix like "-0" is not
    # mistaken for a genuine version disagreement.
    normalized = raw.transform_values { |v| normalize_version(v) }
    primary = normalized[:powershell] || normalized[:platform_dir] || normalized[:file]
    vulnerable = primary.to_s.empty? ? nil : version_below?(primary, datastore['FIXED_VERSION'])
    {
      vulnerable: vulnerable,
      versions: raw,
      primary: primary,
      disagree: normalized.values.reject(&:empty?).uniq.length > 1
    }
  end

  # Extract the dotted numeric core of a version string (e.g. "4.18.26050.15-0" -> "4.18.26050.15").
  def normalize_version(value)
    value.to_s[/\d+(?:\.\d+)+/].to_s
  end

  #
  # ---- (B) Exposed in practice? -------------------------------------------
  #
  def check_posture
    c = collected
    {
      tamper: c['tamper'],
      rtp: c['rtp'],
      behavior: c['behavior'],
      onaccess: c['onaccess'],
      sig_age_days: c['sig_age_days'],
      vss_present: c['shadow_count'].to_i.positive?
    }
  end

  #
  # ---- (C) Targeted? ------------------------------------------------------
  #
  def hunt_targeting
    c = collected
    sig = DEFENDER_SIGNATURE.downcase
    # The threat name lives in structured event data, not on the message's first
    # line, so match against both the extracted threat name and the message.
    sig_hits = Array(c['detections']).select { |e| "#{e['threat']} #{e['msg']}".downcase.include?(sig) }

    feed = iocs
    staged = Array(c['staged'])
    regexes = Array(feed['path_regexes']).map { |r| build_regex(r['pattern']) }.compact
    hashes = Array(feed['file_hashes_sha256']).map { |h| h['value'].to_s.downcase }
                                              .reject { |v| v.empty? || v.start_with?('placeholder') }
    ioc_hits = staged.select do |f|
      path = f['path'].to_s
      hash = f['sha256'].to_s.downcase
      regexes.any? { |re| re.match?(path) } || hashes.include?(hash)
    end

    { sig_hits: sig_hits, ioc_hits: ioc_hits, detection_total: Array(c['detections']).length }
  end

  def build_regex(pattern)
    return nil if pattern.to_s.strip.empty?

    Regexp.new(pattern.to_s, Regexp::IGNORECASE)
  rescue RegexpError
    nil
  end

  def load_iocs
    path = datastore['IOC_FILE'].to_s
    return {} if path.empty? || !::File.file?(path)

    parsed = JSON.parse(::File.read(path))
    unless parsed.is_a?(Hash)
      print_warning("IOC_FILE #{path} must contain a JSON object; skipping IOC matching.")
      return {}
    end

    %w[path_regexes file_hashes_sha256].each do |key|
      next unless parsed.key?(key)

      unless parsed[key].is_a?(Array)
        print_warning("IOC_FILE #{path} field '#{key}' must be an array; skipping it.")
        parsed[key] = []
        next
      end

      kept = parsed[key].select! { |entry| entry.is_a?(Hash) }
      print_warning("IOC_FILE #{path} has invalid '#{key}' entries; skipping them.") if kept
    end
    parsed
  rescue JSON::ParserError
    print_warning("IOC_FILE #{path} is not valid JSON; skipping IOC matching.")
    {}
  end

  # Memoized IOC feed from IOC_FILE (empty hash when unset or invalid).
  def iocs
    @iocs ||= load_iocs
  end

  # True when the feed carries at least one real (non-placeholder) SHA-256 hash, so
  # the collection script only hashes files when hash matching can actually use them.
  def hash_iocs?
    Array(iocs['file_hashes_sha256']).any? do |h|
      v = h['value'].to_s.downcase
      !v.empty? && !v.start_with?('placeholder')
    end
  end

  # True when the feed carries any indicator to match staged files against (a path
  # regex or a hash), so the file scan runs whenever IOC_FILE provides indicators —
  # independent of HUNT_LOG, which gates only the event-log hunt.
  def scan_files?
    Array(iocs['path_regexes']).any? || hash_iocs?
  end

  def version_below?(installed, fixed)
    return false if installed.to_s.empty?

    Rex::Version.new(installed) < Rex::Version.new(fixed)
  rescue ArgumentError
    print_warning("Could not compare version '#{installed}' to '#{fixed}'.")
    false
  end

  #
  # ---- Scoring ------------------------------------------------------------
  #
  def score(version, posture, targeting)
    base =
      if version[:vulnerable]
        'VULNERABLE'
      elsif version[:vulnerable] == false
        weak_posture?(posture) ? 'PATCHED-BUT-EXPOSED' : 'HARDENED'
      else
        'UNKNOWN'
      end
    targeted = !(Array(targeting[:sig_hits]).empty? && Array(targeting[:ioc_hits]).empty?)
    { base: base, targeted: targeted }
  end

  def weak_posture?(posture)
    stale_sig = !posture[:sig_age_days].nil? && posture[:sig_age_days] > SIG_STALE_DAYS
    posture[:tamper] == false || posture[:rtp] == false || posture[:vss_present] == true || stale_sig
  end

  #
  # ---- Reporting ----------------------------------------------------------
  #
  def report(verdict, version, posture, targeting)
    print_line('')
    print_status('== (A) Defender platform version ==')
    version[:versions].each { |src, v| print_status("  #{src}: #{v}") }
    print_warning('  version sources disagree (possible tampering / partial update)') if version[:disagree]
    case version[:vulnerable]
    when true then print_warning("  #{version[:primary]} is BELOW fixed build #{datastore['FIXED_VERSION']}")
    when false then print_good("  #{version[:primary]} includes the fix")
    else print_status('  version could not be determined')
    end

    print_line('')
    print_status('== (B) Posture ==')
    print_status("  Tamper Protection: #{posture[:tamper]}   Real-time: #{posture[:rtp]}")
    print_status("  Behavior monitor: #{posture[:behavior]}   On-access: #{posture[:onaccess]}")
    print_status("  Signature age (days): #{posture[:sig_age_days]}   Shadow copies present: #{posture[:vss_present]}")

    print_line('')
    print_status('== (C) Targeting evidence ==')
    print_status("  Defender detections in window (1116/1117): #{targeting[:detection_total]}")
    Array(targeting[:sig_hits]).each { |e| print_warning("  BlueHammer signature hit [#{e['time']}] #{e['threat'].to_s.empty? ? e['msg'] : e['threat']}") }
    Array(targeting[:ioc_hits]).each { |f| print_error("  IOC match: #{f['path']}") }
    print_good('  no BlueHammer signature or IOC matches') unless verdict[:targeted]

    print_line('')
    print_status('== Verdict ==')
    print_good("Verdict: #{verdict[:base]}")
    print_error('EVIDENCE-OF-TARGETING: Defender log / IOC hits present.') if verdict[:targeted]

    data = {
      cve: 'CVE-2026-33825', verdict: verdict, version: version,
      posture: posture, targeting: targeting,
      generated: Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    if verdict[:base] == 'VULNERABLE'
      report_vuln(
        host: session.session_host,
        name: 'Microsoft Defender BlueHammer (CVE-2026-33825) — vulnerable platform',
        refs: references,
        info: "Defender platform below fixed build #{datastore['FIXED_VERSION']}"
      )
    end

    report_note(host: session.session_host, type: 'bluehammer.audit', data: data, update: :unique_data)

    return unless datastore['STORE_LOOT']

    path = store_loot('bluehammer.audit', 'application/json', session.session_host,
                      JSON.pretty_generate(data), 'bluehammer_defender_audit.json',
                      'BlueHammer CVE-2026-33825 defensive audit snapshot')
    print_good("Loot snapshot: #{path}")
  end
end
