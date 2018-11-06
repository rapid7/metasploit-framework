module RubySMB
  # Namespace for structures and classes from File System
  # Control Codes as defined in
  # [[MS-FSCC]: File System Control Codes](https://msdn.microsoft.com/en-us/library/cc231987.aspx)
  module Fscc
    require 'ruby_smb/fscc/file_attributes'
    require 'ruby_smb/fscc/file_full_ea_info'
    require 'ruby_smb/fscc/ea_info_array'
    require 'ruby_smb/fscc/file_information'
    require 'ruby_smb/fscc/control_codes'
  end
end
