module RubySMB
  module SMB1
    module BitField
      # The AccessMode bit-field for an SMB1 Open2 Request as defined in
      # [2.2.6.1.1 Request](https://msdn.microsoft.com/en-us/library/ee441733.aspx)
      class Open2AccessMode < BinData::Record
        endian  :little
        bit1    :reserved2,           label: 'Reserved Space'
        bit3    :sharing_mode,        label: 'Sharing Mode'
        bit1    :reserved,            label: 'Reserved Space'
        bit3    :access_mode,         label: 'Access Mode'
        # byte boundary
        bit1    :reserved5,           label: 'Reserved Space'
        bit1    :writethrough,        label: 'Writethrough mode'
        bit1    :reserved4,           label: 'Reserved Space'
        bit1    :cache_mode,          label: 'Cache Mode'
        bit1    :reserved3,           label: 'Reserved Space'
        bit3    :reference_locality,  label: 'Reference'

        # Sets the #access_mode based on more human readableinput.
        # Takes the symbols :r, :w, :rw, and :x to set Read, Write,
        # ReadWrite, and Execute respectively.
        #
        # @param mode [Symbol] the access mode to set
        def set_access_mode(mode = :r)
          modes = [:r, :w, :rw, :x]
          raise ArgumentError, "Mode must be one of #{modes}" unless modes.include? mode
          case mode
          when :r
            self.access_mode = 0
          when :w
            self.access_mode = 1
          when :rw
            self.access_mode = 2
          when :x
            self.access_mode = 3
          end
        end
      end
    end
  end
end
