# -*- coding: binary -*-

module Msf
  class Post
    module Linux
      module Kernel
        include ::Msf::Post::Common
        include Msf::Post::File

        #
        # Returns uname output
        #
        # @param opt [String] uname options, defaults to -a
        # @return [String]
        # @raise [RuntimeError] If execution fails.
        #
        def uname(opts = '-a')
          cmd_exec("uname #{opts}").to_s.strip
        rescue StandardError
          raise "Failed to run uname #{opts}"
        end

        #
        # Returns the kernel release
        #
        # @return [String]
        #
        def kernel_release
          uname('-r')
        end

        #
        # Returns the kernel version
        #
        # @return [String]
        #
        def kernel_version
          uname('-v')
        end

        #
        # Returns the kernel name
        #
        # @return [String]
        #
        def kernel_name
          uname('-s')
        end

        #
        # Returns the kernel hardware
        #
        # @return [String]
        #
        def kernel_hardware
          uname('-m')
        end

        #
        # Returns the kernel hardware architecture
        # Based on values from https://en.wikipedia.org/wiki/Uname
        #
        # @return [String]
        #
        def kernel_arch
          arch = kernel_hardware
          return ARCH_X64 if arch == 'x86_64' || arch == 'amd64'
          return ARCH_AARCH64 if arch == 'aarch64' || arch == 'arm64'
          return ARCH_ARMLE if arch.start_with? 'arm'
          return ARCH_X86 if arch.end_with? '86'
          return ARCH_PPC if arch == 'ppc'
          return ARCH_PPC64 if arch == 'ppc64'
          return ARCH_PPC64LE if arch == 'ppc64le'
          return ARCH_MIPS if arch == 'mips'
          return ARCH_MIPS64 if arch == 'mips64'
          return ARCH_SPARC if arch == 'sparc'
          return ARCH_RISCV32LE if arch == 'riscv32'
          return ARCH_RISCV64LE if arch == 'riscv64'
          return ARCH_LOONGARCH64 if arch == 'loongarch64'

          arch
        end

        #
        # Returns the kernel boot config with comments removed
        #
        # @return [Array]
        # @raise [RuntimeError] If execution fails.
        #
        def kernel_config
          release = kernel_release
          output = read_file("/boot/config-#{release}").to_s.strip
          return if output.empty?

          config = output.split("\n").map(&:strip).reject(&:empty?).reject { |i| i.start_with? '#' }
          config
        rescue StandardError
          raise 'Could not retrieve kernel config'
        end

        #
        # Returns the kernel modules
        #
        # @return [Array]
        # @raise [RuntimeError] If execution fails.
        #
        def kernel_modules
          read_file('/proc/modules').to_s.scan(/^[^ ]+/)
        rescue StandardError
          raise 'Could not determine kernel modules'
        end

        #
        # Returns a list of CPU flags
        #
        # @return [Array]
        # @raise [RuntimeError] If execution fails.
        #
        def cpu_flags
          cpuinfo = read_file('/proc/cpuinfo').to_s

          return unless cpuinfo.include? 'flags'

          cpuinfo.scan(/^flags\s*:(.*)$/).flatten.join(' ').split(/\s/).map(&:strip).reject(&:empty?).uniq
        rescue StandardError
          raise 'Could not retrieve CPU flags'
        end

        #
        # Returns true if kernel and hardware supports Supervisor Mode Access Prevention (SMAP), false if not.
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def smap_enabled?
          cpu_flags.include? 'smap'
        rescue StandardError
          raise 'Could not determine SMAP status'
        end

        #
        # Returns true if kernel and hardware supports Supervisor Mode Execution Protection (SMEP), false if not.
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def smep_enabled?
          cpu_flags.include? 'smep'
        rescue StandardError
          raise 'Could not determine SMEP status'
        end

        #
        # Returns true if Kernel Address Isolation (KAISER) is enabled
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def kaiser_enabled?
          cpu_flags.include? 'kaiser'
        rescue StandardError
          raise 'Could not determine KAISER status'
        end

        #
        # Returns true if Kernel Page-Table Isolation (KPTI) is enabled, false if not.
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def kpti_enabled?
          cpu_flags.include? 'pti'
        rescue StandardError
          raise 'Could not determine KPTI status'
        end

        #
        # Returns true if user namespaces are enabled, false if not.
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def userns_enabled?
          return false if read_file('/proc/sys/user/max_user_namespaces').to_s.strip.eql? '0'
          return false if read_file('/proc/sys/kernel/unprivileged_userns_clone').to_s.strip.eql? '0'

          true
        rescue StandardError
          raise 'Could not determine userns status'
        end

        #
        # Returns true if Address Space Layout Randomization (ASLR) is enabled
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def aslr_enabled?
          aslr = read_file('/proc/sys/kernel/randomize_va_space').to_s.strip
          aslr.eql?('1') || aslr.eql?('2')
        rescue StandardError
          raise 'Could not determine ASLR status'
        end

        #
        # Returns true if Exec-Shield is enabled
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def exec_shield_enabled?
          exec_shield = read_file('/proc/sys/kernel/exec-shield').to_s.strip
          exec_shield.eql?('1') || exec_shield.eql?('2')
        rescue StandardError
          raise 'Could not determine exec-shield status'
        end

        #
        # Returns true if unprivileged bpf is disabled
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def unprivileged_bpf_disabled?
          unprivileged_bpf_disabled = read_file('/proc/sys/kernel/unprivileged_bpf_disabled').to_s.strip
          return unprivileged_bpf_disabled == '1' || unprivileged_bpf_disabled == '2'
        rescue StandardError
          raise 'Could not determine kernel.unprivileged_bpf_disabled status'
        end

        #
        # Returns true if kernel pointer restriction is enabled
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def kptr_restrict?
          read_file('/proc/sys/kernel/kptr_restrict').to_s.strip.eql? '1'
        rescue StandardError
          raise 'Could not determine kernel.kptr_restrict status'
        end

        #
        # Returns true if dmesg restriction is enabled
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def dmesg_restrict?
          read_file('/proc/sys/kernel/dmesg_restrict').to_s.strip.eql? '1'
        rescue StandardError
          raise 'Could not determine kernel.dmesg_restrict status'
        end

        #
        # Returns mmap minimum address
        #
        # @return [Integer]
        # @raise [RuntimeError] If execution fails.
        #
        def mmap_min_addr
          mmap_min_addr = read_file('/proc/sys/vm/mmap_min_addr').to_s.strip
          return 0 unless mmap_min_addr =~ /\A\d+\z/

          mmap_min_addr
        rescue StandardError
          raise 'Could not determine system mmap_min_addr'
        end

        #
        # Returns true if Linux Kernel Runtime Guard (LKRG) kernel module is installed
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def lkrg_installed?
          directory?('/proc/sys/lkrg')
        rescue StandardError
          raise 'Could not determine LKRG status'
        end

        #
        # Returns true if grsecurity is installed
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def grsec_installed?
          cmd_exec('test -c /dev/grsec && echo true').to_s.strip.include? 'true'
        rescue StandardError
          raise 'Could not determine grsecurity status'
        end

        #
        # Returns true if PaX is installed
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def pax_installed?
          read_file('/proc/self/status').to_s.include? 'PaX:'
        rescue StandardError
          raise 'Could not determine PaX status'
        end

        #
        # Returns true if SELinux is installed
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def selinux_installed?
          cmd_exec('id').to_s.include? 'context='
        rescue StandardError
          raise 'Could not determine SELinux status'
        end

        #
        # Returns true if SELinux is in enforcing mode
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def selinux_enforcing?
          return false unless selinux_installed?

          sestatus = cmd_exec('/usr/sbin/sestatus').to_s.strip
          raise unless sestatus.include?('SELinux')

          return true if sestatus =~ /Current mode:\s*enforcing/

          false
        rescue StandardError
          raise 'Could not determine SELinux status'
        end

        #
        # Returns Yama LSM ptrace scope level
        #
        # @return [Integer] Yama ptrace scope level (0 if disabled or not installed)
        # @raise [RuntimeError] If execution fails.
        #
        def yama_ptrace_scope
          ptrace_scope = read_file('/proc/sys/kernel/yama/ptrace_scope').to_s.strip

          return 0 unless ptrace_scope

          level = ptrace_scope.scan(/\A(\d+)\z/).flatten.first.to_i

          return 0 unless level

          level
        rescue StandardError
          raise 'Could not determine Yama scope'
        end

        #
        # Returns true if Yama is installed
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def yama_installed?
          ptrace_scope = read_file('/proc/sys/kernel/yama/ptrace_scope').to_s.strip
          return true if ptrace_scope =~ /\A\d\z/

          false
        rescue StandardError
          raise 'Could not determine Yama status'
        end

        #
        # Returns true if Yama is enabled
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def yama_enabled?
          yama_ptrace_scope > 0
        rescue StandardError
          raise 'Could not determine Yama status'
        end
      end
    end
  end
end
