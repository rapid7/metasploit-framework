module RubySMB
  module SMB2
    module BitField
      # A Share Flags BitField Mask as defined in
      # [2.2.10 SMB2 TREE_CONNECT Response](https://msdn.microsoft.com/en-us/library/cc246499.aspx)
      class ShareFlags < BinData::Record
        endian  :little
        bit2    :reserved1,                 label: 'Reserved Space'
        bit1    :vdo_caching,               label: 'VDO Caching'
        bit1    :auto_caching,              label: 'Auto Caching'
        bit2    :reserved2
        bit1    :dfs_root,                  label: 'DFS Root'
        bit1    :dfs,                       label: 'DFS'
        # byte boundary
        bit1    :encrypt,                   label: 'Encrypted Data Required'
        bit1    :hash_v2,                   label: 'Hash Generation V2'
        bit1    :hash_v1,                   label: 'Hash Generation V1'
        bit1    :force_oplock,              label: 'Force Lvl2 OpLocks'
        bit1    :access_based_enum,         label: 'Access Based Directory Enumeration'
        bit1    :namespace_caching,         label: 'Namespace Caching'
        bit1    :shared_delete,             label: 'Force Shared Delete'
        bit1    :restrict_exclusive_opens,  label: 'Restrict Exclusive Opens'

        bit8    :reserved3,                 label: 'Reserved Space'
        bit8    :reserved4,                 label: 'Reserved Space'

        def caching_type
          if vdo_caching == 1 && auto_caching.zero?
            :vdo
          elsif vdo_caching.zero? && auto_caching == 1
            :auto
          elsif vdo_caching == 1 && auto_caching == 1
            :no_caching
          else
            :manual
          end
        end

        # Sets the Bit Mask for Manual Caching
        #
        # @return [void]
        def set_manual_caching
          self.vdo_caching  = 0
          self.auto_caching = 0
        end

        # Sets the Bit Mask for Auto Caching
        #
        # @return [void]
        def set_auto_caching
          self.vdo_caching  = 0
          self.auto_caching = 1
        end

        # Sets the Bit Mask for VDO Caching
        #
        # @return [void]
        def set_vdo_caching
          self.vdo_caching  = 1
          self.auto_caching = 0
        end

        # Sets the Bit Mask for No Caching
        #
        # @return [void]
        def set_no_caching
          self.vdo_caching  = 1
          self.auto_caching = 1
        end
      end
    end
  end
end
