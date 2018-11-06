module RubySMB
  module SMB1
    # This module holds the Create Actions used in NT_TRANSACT_CREATE and
    # SMB_COM_NT_CREATE_ANDX responses. The definitions for these values can be found at
    # [2.2.7.1.2 Response](https://msdn.microsoft.com/en-us/library/ee441961.aspx)
    module CreateActions
      # An existing file was deleted and a new file was created in its place.
      FILE_SUPERSEDED = 0x00000000

      # An existing file was opened.
      FILE_OPENED = 0x00000001

      # A new file was created.
      FILE_CREATED       = 0x00000002

      # An existing file was overwritten.
      FILE_OVERWRITEN    = 0x00000003
    end
  end
end
