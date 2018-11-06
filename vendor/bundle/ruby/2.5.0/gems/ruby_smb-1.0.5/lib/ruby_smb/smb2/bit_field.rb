module RubySMB
  module SMB2
    # Namespace for BitMask style field definitions
    module BitField
      require 'ruby_smb/smb2/bit_field/smb2_header_flags'
      require 'ruby_smb/smb2/bit_field/smb2_security_mode'
      require 'ruby_smb/smb2/bit_field/smb2_security_mode_single'
      require 'ruby_smb/smb2/bit_field/smb2_capabilities'
      require 'ruby_smb/smb2/bit_field/session_flags'
      require 'ruby_smb/smb2/bit_field/directory_access_mask'
      require 'ruby_smb/smb2/bit_field/file_access_mask'
      require 'ruby_smb/smb2/bit_field/share_flags'
      require 'ruby_smb/smb2/bit_field/share_capabilities'
    end
  end
end
