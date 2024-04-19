require 'mysql'

module Rex
  module Proto
    module MySQL

      # This is a Rex Proto wrapper around the ::Mysql client which is currently coming from the 'ruby-mysql' gem.
      # The purpose of this wrapper is to provide 'peerhost' and 'peerport' methods to ensure the client interfaces
      # are consistent between various SQL implementations/protocols.
      class Client < ::Mysql
        # @return [String] The remote IP address that the Mysql server is running on
        def peerhost
          io.remote_address.ip_address
        end

        # @return [Integer] The remote port that the Mysql server is running on
        def peerport
          io.remote_address.ip_port
        end

        # @return [String] The remote peer information containing IP and port
        def peerinfo
          "#{peerhost}:#{peerport}"
        end

        # @return [String] The database this client is currently connected to
        def current_database
          # Current database is stored as an array under the type 1 key.
          session_track.fetch(1, ['']).first
        end

        # List of supported MySQL platforms & architectures:
        # https://www.mysql.com/support/supportedplatforms/database.html
        def map_compile_os_to_platform(compile_os)
          return '' if compile_os.blank?

          compile_os = compile_os.downcase.encode(::Encoding::BINARY)

          if compile_os.match?('linux')
            platform = Msf::Platform::Linux.realname
          elsif compile_os.match?('unix')
            platform = Msf::Platform::Unix.realname
          elsif compile_os.match?(/(darwin|mac|osx)/)
            platform = Msf::Platform::OSX.realname
          elsif compile_os.match?('win')
            platform = Msf::Platform::Windows.realname
          elsif compile_os.match?('solaris')
            platform = Msf::Platform::Solaris.realname
          else
            platform = compile_os
          end

          platform
        end

        def map_compile_arch_to_architecture(compile_arch)
          return '' if compile_arch.blank?

          compile_arch = compile_arch.downcase.encode(::Encoding::BINARY)

          if compile_arch.match?('sparc')
            if compile_arch.include?('64')
              arch = ARCH_SPARC64
            else
              arch = ARCH_SPARC
            end
          elsif compile_arch.match?('arm')
            if compile_arch.match?('64')
              arch = ARCH_AARCH64
            elsif compile_arch.match?('arm')
              arch = ARCH_ARMLE
            end
          elsif compile_arch.match?('64')
            arch = ARCH_X86_64
          elsif compile_arch.match?('86') || compile_arch.match?('i686')
            arch = ARCH_X86
          else
            arch = compile_arch
          end

          arch
        end

        # @return [Hash] Detect the platform and architecture of the MySQL server:
        #  * :arch [String] The server architecture.
        #  * :platform [String] The server platform.
        def detect_platform_and_arch
          result = {}

          server_vars = query("show variables where variable_name in ('version_compile_machine', 'version_compile_os')").entries.to_h
          result[:arch] = map_compile_arch_to_architecture(server_vars['version_compile_machine'])
          result[:platform] = map_compile_os_to_platform(server_vars['version_compile_os'])

          result
        end
      end
    end
  end
end
