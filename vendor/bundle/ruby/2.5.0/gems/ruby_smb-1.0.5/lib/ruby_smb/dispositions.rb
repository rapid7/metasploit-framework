module RubySMB
  # This module holds the Create Dispositions used in NT_TRANSACT_CREATE and
  # SMB_COM_NT_CREATE_ANDX requests. The definitions for these values can be found at
  # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
  module Dispositions
    # If the file already exists, it SHOULD be superseded (overwritten).
    # If it does not already exist, it SHOULD be created.
    FILE_SUPERSEDE    = 0x00000000

    # If the file already exists, it SHOULD be opened rather than creating a new file.
    # If the file does not already exist, the operation MUST fail.
    FILE_OPEN         = 0x00000001

    # If the file already exists, the operation MUST fail.
    # If the file does not already exist, it SHOULD be created.
    FILE_CREATE       = 0x00000002

    # If the file already exists, it SHOULD be opened.
    # If the file does not already exist, it SHOULD be created.
    FILE_OPEN_IF      = 0x00000003

    # If the file already exists, it SHOULD be opened and truncated.
    # If the file does not already exist, the operation MUST fail.
    # The client MUST open the file with at least GENERIC_WRITE access for the command to succeed.
    FILE_OVERWRITE    = 0x00000004

    # If the file already exists, it SHOULD be opened and truncated.
    # If the file does not already exist, it SHOULD be created.
    # The client MUST open the file with at least GENERIC_WRITE access.
    FILE_OVERWRITE_IF = 0x00000005
  end
end
