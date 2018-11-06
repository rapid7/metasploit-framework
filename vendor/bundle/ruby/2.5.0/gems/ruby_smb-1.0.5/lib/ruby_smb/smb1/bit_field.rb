module RubySMB
  module SMB1
    # Namespace for SMB1 Bit Mask style field definitions
    module BitField
      require 'ruby_smb/smb1/bit_field/header_flags'
      require 'ruby_smb/smb1/bit_field/header_flags2'
      require 'ruby_smb/smb1/bit_field/security_mode'
      require 'ruby_smb/smb1/bit_field/capabilities'
      require 'ruby_smb/smb1/bit_field/tree_connect_flags'
      require 'ruby_smb/smb1/bit_field/optional_support'
      require 'ruby_smb/smb1/bit_field/directory_access_mask'
      require 'ruby_smb/smb1/bit_field/file_access_mask'
      require 'ruby_smb/smb1/bit_field/trans_flags'
      require 'ruby_smb/smb1/bit_field/open2_flags'
      require 'ruby_smb/smb1/bit_field/open2_access_mode'
      require 'ruby_smb/smb1/bit_field/open2_open_mode'
      require 'ruby_smb/smb1/bit_field/smb_file_attributes'
      require 'ruby_smb/smb1/bit_field/smb_ext_file_attributes'
      require 'ruby_smb/smb1/bit_field/smb_nmpipe_status'
      require 'ruby_smb/smb1/bit_field/share_access'
      require 'ruby_smb/smb1/bit_field/create_options'
      require 'ruby_smb/smb1/bit_field/security_flags'
      require 'ruby_smb/smb1/bit_field/file_status_flags'
    end
  end
end
