module RubySMB
  module SMB2
    # Contains constants for the InfoType values as defined in
    # [2.2.39 SMB2 SET_INFO Request](https://msdn.microsoft.com/en-us/library/cc246560.aspx) and
    # [2.2.37 SMB2 QUERY_INFO Request](https://msdn.microsoft.com/en-us/library/cc246557.aspx)
    module InfoType
      # The file information
      SMB2_0_INFO_FILE       = 0x01

      # The underlying object store information
      SMB2_0_INFO_FILESYSTEM = 0x02

      # The security information
      SMB2_0_INFO_SECURITY   = 0x03

      # The underlying object store quota information
      SMB2_0_INFO_QUOTA      = 0x04
    end
  end
end

