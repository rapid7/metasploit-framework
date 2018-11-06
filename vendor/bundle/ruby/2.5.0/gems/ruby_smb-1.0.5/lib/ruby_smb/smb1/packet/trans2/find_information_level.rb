module RubySMB
  module SMB1
    module Packet
      module Trans2
        # FIND information levels are used in TRANS2_FIND_FIRST2 (section 2.2.6.2) and
        # TRANS2_FIND_NEXT2 (section 2.2.6.3) subcommand requests to indicate the level
        # of information that a server MUST respond with for each file matching the
        # request's search criteria.
        module FindInformationLevel
          # Return creation, access, and last write timestamps, size and file attributes along with the file name.
          SMB_INFO_STANDARD                 = 0x0001
          # Return the SMB_INFO_STANDARD data along with the size of a file's extended attributes (EAs).
          SMB_INFO_QUERY_EA_SIZE            = 0x0002
          # Return the SMB_INFO_QUERY_EA_SIZE data along with a specific list of a file's EAs. The requested EAs are provided in the Trans2_Data block of the request.
          SMB_INFO_QUERY_EAS_FROM_LIST      = 0x0003
          # Return 64-bit format versions of: creation, access, last write, and last attribute change timestamps; size. In addition, return extended file attributes and file name.
          SMB_FIND_FILE_DIRECTORY_INFO      = 0x0101
          # Returns the SMB_FIND_FILE_DIRECTORY_INFO data along with the size of a file's EAs.
          SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x0102
          # Returns the name(s) of the file(s).
          SMB_FIND_FILE_NAMES_INFO          = 0x0103
          # Returns a combination of the data from SMB_FIND_FILE_FULL_DIRECTORY_INFO and SMB_FIND_FILE_NAMES_INFO.
          SMB_FIND_FILE_BOTH_DIRECTORY_INFO = 0x0104


          require 'ruby_smb/smb1/packet/trans2/find_information_level/find_file_full_directory_info'

        end
      end
    end
  end
end
