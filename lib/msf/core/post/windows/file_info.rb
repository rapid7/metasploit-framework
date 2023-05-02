# -*- coding: binary -*-

module Msf
  class Post
    module Windows
      # Provides helpers to get file and product versions
      module FileInfo
        class FileInfoError < StandardError; end

        # A VS_FIXEDFILEINFO structure as defined here:
        # https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
        class VsFixedFileInfo < BinData::Record
          endian :little

          uint32 :signature, initial_value: 0xfeef04bd, assert: 0xfeef04bd
          uint32 :struc_version
          uint32 :file_version_ms
          uint32 :file_version_ls
          uint32 :product_version_ms
          uint32 :product_version_ls
          uint32 :file_flags_mask
          uint32 :file_flags
          uint32 :file_os
          uint32 :file_type
          uint32 :file_subtype
          uint32 :file_date_ms
          uint32 :file_date_ls

          def file_version_major
            hiword(file_version_ms)
          end

          def file_version_minor
            loword(file_version_ms)
          end

          def file_version_build
            hiword(product_version_ls)
          end

          def file_version_revision
            loword(product_version_ls)
          end

          def file_version_branch
            file_version_revision.to_s[0..1].to_i
          end

          def product_version_major
            hiword(product_version_ms)
          end

          def product_version_minor
            loword(product_version_ms)
          end

          def product_version_build
            hiword(product_version_ls)
          end

          def product_version_revision
            loword(product_version_ls)
          end

          def product_version_branch
            product_version_revision.to_s[0..1].to_i
          end

          private

          def hiword(num)
            (num >> 16) & 0xffff
          end

          def loword(num)
            num & 0xffff
          end

        end

        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_railgun_api
                    stdapi_railgun_memread
                  ]
                }
              }
            )
          )
        end

        # Returns the file's binary version number.
        #
        # Note that, since Windows 8.1, the file version depends on how the file is
        # manifested. When it is not manifested, it will always return the Windows 8
        # version value (6.2) for any newer Windows version (Windows 8.1, 10, 11,
        # etc.). When the application is manifested, it will always return the version
        # that the application is manifested for.
        # See https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexa
        #
        #
        # @param filepath [String] The path of the file
        # @return [Array<String>] Returns the file version information of the file as
        #   an array such as: major, minor, build, revision, branch
        # @raise [Msf::Post::Windows::FileInfo::FileInfoError]
        def file_version(filepath)
          vs_fixed_file_info = get_vs_fixed_file_info(filepath)

          return [
            vs_fixed_file_info.file_version_major,
            vs_fixed_file_info.file_version_minor,
            vs_fixed_file_info.file_version_build,
            vs_fixed_file_info.file_version_revision,
            vs_fixed_file_info.file_version_branch
          ]
        end

        # Returns the product version number of a file, which is the binary version
        # number of the product with which this file was distributed.
        #
        # @param filepath [String] The path of the file
        # @return [Array<String>] Returns the product version information of the file
        #   as an array such as: major, minor, build, revision, branch
        # @raise [Msf::Post::Windows::FileInfo::FileInfoError]
        def product_version(filepath)
          vs_fixed_file_info = get_vs_fixed_file_info(filepath)

          return [
            vs_fixed_file_info.product_version_major,
            vs_fixed_file_info.product_version_minor,
            vs_fixed_file_info.product_version_build,
            vs_fixed_file_info.product_version_revision,
            vs_fixed_file_info.product_version_branch
          ]
        end

        # Returns a VsFixedFileInfo BinData structure containing information of the file at `filepath`.
        # see https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
        #
        # @param filepath [String] The path of the file
        # @return [Msf::Post::Windows::FileInfo::VsFixedFileInfo] VS_FIXEDFILEINFO structure
        # @raise [Msf::Post::Windows::FileInfo::FileInfoError]
        def get_vs_fixed_file_info(filepath)
          file_version_info_size = client.railgun.version.GetFileVersionInfoSizeA(
            filepath,
            nil
          )['return']

          if file_version_info_size == 0
            # Indicates an error - should not continue
            return nil
          end

          buffer = session.railgun.kernel32.VirtualAlloc(
            nil,
            file_version_info_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
          )['return']

          client.railgun.version.GetFileVersionInfoA(
            filepath,
            0,
            file_version_info_size,
            buffer
          )

          result = client.railgun.version.VerQueryValueA(buffer, '\\', 4, 4)
          ffi = client.railgun.memread(result['lplpBuffer'], result['puLen'])

          return VsFixedFileInfo.read(ffi)
        rescue BinData::ValidityError, IOError => e
          msg = "Unable to parse the VS_FIXEDFILEINFO structure from filepath #{filepath}: #{e}"
          elog(msg, error: e)
          raise FileInfoError, msg
        rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError => e
          msg = "Communication error while getting file information for #{filepath}: #{e}"
          elog(msg, error: e)
          raise FileInfoError, msg
        end
      end
    end
  end
end
