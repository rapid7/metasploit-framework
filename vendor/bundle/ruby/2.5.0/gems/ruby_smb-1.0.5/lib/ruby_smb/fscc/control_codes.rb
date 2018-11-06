module RubySMB
  module Fscc

    # Defines the FSCTL/IOCTL control codes as defined in
    # [2.2.31 SMB2 IOCTL Request](https://msdn.microsoft.com/en-us/library/cc246545.aspx)
    module ControlCodes

      FSCTL_DFS_GET_REFERRALS             = 0x00060194
      FSCTL_PIPE_PEEK                     = 0x0011400C
      FSCTL_PIPE_WAIT                     = 0x00110018
      FSCTL_PIPE_TRANSCEIVE               = 0x0011C017
      FSCTL_SRV_COPYCHUNK                 = 0x001440F2
      FSCTL_SRV_ENUMERATE_SNAPSHOTS       = 0x00144064
      FSCTL_SRV_REQUEST_RESUME_KEY        = 0x00140078
      FSCTL_SRV_READ_HASH                 = 0x001441bb
      FSCTL_SRV_COPYCHUNK_WRITE           = 0x001480F2
      FSCTL_LMR_REQUEST_RESILIENCY        = 0x001401D4
      FSCTL_QUERY_NETWORK_INTERFACE_INFO  = 0x001401FC
      FSCTL_SET_REPARSE_POINT             = 0x000900A4
      FSCTL_DFS_GET_REFERRALS_EX          = 0x000601B0
      FSCTL_FILE_LEVEL_TRIM               = 0x00098208
      FSCTL_VALIDATE_NEGOTIATE_INFO       = 0x00140204

    end
  end
end