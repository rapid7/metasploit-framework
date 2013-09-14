# -*- coding: binary -*-
module Rex
module Proto
module DCERPC
module Exceptions

class Error < ::RuntimeError

  @@errors = {
    0x00000000 => "stub-defined",
    0x00000001 => "nca_s_fault_other",
    0x00000005 => "nca_s_fault_access_denied",
    0x000006d8 => "nca_s_fault_cant_perform",
    0x000006f7 => "nca_s_fault_ndr",
    0x16c9a001 => "rpc_s_op_rng_error",
    0x16c9a006 => "rpc_s_wrong_boot_time",
    0x16c9a012 => "rpc_s_no_memory",
    0x16c9a016 => "rpc_s_comm_failure",
    0x16c9a01b => "rpc_s_fault_object_not_found",
    0x16c9a02c => "rpc_s_unknown_if",
    0x16c9a02d => "rpc_s_unsupported_type",
    0x16c9a030 => "rpc_s_cancel_timeout",
    0x16c9a031 => "rpc_s_call_cancelled",
    0x16c9a036 => "rpc_s_connection_closed",
    0x16c9a041 => "rpc_s_connect_timed_out",
    0x16c9a042 => "rpc_s_connect_rejected",
    0x16c9a043 => "rpc_s_network_unreachable",
    0x16c9a044 => "rpc_s_connect_no_resources",
    0x16c9a045 => "rpc_s_rem_network_shutdown",
    0x16c9a046 => "rpc_s_too_many_rem_connects",
    0x16c9a047 => "rpc_s_no_rem_endpoint",
    0x16c9a048 => "rpc_s_rem_host_down",
    0x16c9a049 => "rpc_s_host_unreachable",
    0x16c9a04a => "rpc_s_access_control_info_inv",
    0x16c9a04b => "rpc_s_loc_connect_aborted",
    0x16c9a04c => "rpc_s_connect_closed_by_rem",
    0x16c9a04d => "rpc_s_rem_host_crashed",
    0x16c9a074 => "rpc_s_fault_addr_error",
    0x16c9a075 => "rpc_s_fault_context_mismatch",
    0x16c9a076 => "rpc_s_fault_fp_div_by_zero",
    0x16c9a077 => "rpc_s_fault_fp_error",
    0x16c9a078 => "rpc_s_fault_fp_overflow",
    0x16c9a079 => "rpc_s_fault_fp_underflow",
    0x16c9a07a => "rpc_s_fault_ill_inst",
    0x16c9a07b => "rpc_s_fault_int_div_by_zero",
    0x16c9a07c => "rpc_s_fault_int_overflow",
    0x16c9a07d => "rpc_s_fault_invalid_bound",
    0x16c9a07e => "rpc_s_fault_invalid_tag",
    0x16c9a07f => "rpc_s_fault_pipe_closed",
    0x16c9a080 => "rpc_s_fault_pipe_comm_error",
    0x16c9a081 => "rpc_s_fault_pipe_discipline",
    0x16c9a082 => "rpc_s_fault_pipe_empty",
    0x16c9a083 => "rpc_s_fault_pipe_memory",
    0x16c9a084 => "rpc_s_fault_pipe_order",
    0x16c9a085 => "rpc_s_fault_remote_comm_failure",
    0x16c9a086 => "rpc_s_fault_remote_no_memory",
    0x16c9a087 => "rpc_s_fault_unspec",
    0x16c9a0a8 => "rpc_s_no_ns_permission",
    0x16c9a0b5 => "rpc_s_no_more_bindings",
    0x16c9a113 => "rpc_s_fault_user_defined",
    0x16c9a116 => "rpc_s_fault_tx_open_failed",
    0x16c9a16e => "rpc_s_fault_codeset_conv_error",
    0x16c9a170 => "rpc_s_fault_no_client_stub",
    0x1c000001 => "nca_s_fault_int_div_by_zero",
    0x1c000002 => "nca_s_fault_addr_error",
    0x1c000003 => "nca_s_fault_fp_div_zero",
    0x1c000004 => "nca_s_fault_fp_underflow",
    0x1c000005 => "nca_s_fault_fp_overflow",
    0x1c000006 => "nca_s_fault_invalid_tag",
    0x1c000007 => "nca_s_fault_invalid_bound",
    0x1c000008 => "nca_rpc_version_mismatch",
    0x1c000009 => "nca_unspec_reject",
    0x1c00000a => "nca_s_bad_actid",
    0x1c00000b => "nca_who_are_you_failed",
    0x1c00000c => "nca_manager_not_entered",
    0x1c00000d => "nca_s_fault_cancel",
    0x1c00000e => "nca_s_fault_ill_inst",
    0x1c00000f => "nca_s_fault_fp_error",
    0x1c000010 => "nca_s_fault_int_overflow",
    0x1c000014 => "nca_s_fault_pipe_empty",
    0x1c000015 => "nca_s_fault_pipe_closed",
    0x1c000016 => "nca_s_fault_pipe_order",
    0x1c000017 => "nca_s_fault_pipe_discipline",
    0x1c000018 => "nca_s_fault_pipe_comm_error",
    0x1c000019 => "nca_s_fault_pipe_memory",
    0x1c00001a => "nca_s_fault_context_mismatch",
    0x1c00001b => "nca_s_fault_remote_no_memory",
    0x1c00001c => "nca_invalid_pres_context_id",
    0x1c00001d => "nca_unsupported_authn_level",
    0x1c00001f => "nca_invalid_checksum",
    0x1c000020 => "nca_invalid_crc",
    0x1c000021 => "ncs_s_fault_user_defined",
    0x1c000022 => "nca_s_fault_tx_open_failed",
    0x1c000023 => "nca_s_fault_codeset_conv_error",
    0x1c000024 => "nca_s_fault_object_not_found",
    0x1c000025 => "nca_s_fault_no_client_stub",
    0x1c010002 => "nca_op_rng_error",
    0x1c010003 => "nca_unk_if",
    0x1c010006 => "nca_wrong_boot_time",
    0x1c010009 => "nca_s_you_crashed",
    0x1c01000b => "nca_proto_error",
    0x1c010013 => "nca_out_args_too_big",
    0x1c010014 => "nca_server_too_busy",
    0x1c010017 => "nca_unsupported_type"
  }

  def initialize(*args)
    super(*args)
  end

  # returns an error string if it exists, otherwise just the error code
  def get_error(error)
    string = ''
    if @@errors[error]
      string = @@errors[error]
    else
      string = sprintf('0x%.8x',error)
    end
  end
end

class Fault < Error
  attr_accessor :fault
  def to_s
    'DCERPC FAULT => ' + get_error(self.fault)
  end
end

class NoResponse < Error
  def to_s
    'no response from dcerpc service'
  end
end

class InvalidPacket < Error
  def initialize(message = nil)
    @message = message
  end

  def to_s
    str = 'Invalid packet.'
    if (@message)
      str += " #{@message}"
    end
  end
end

end
end
end
end
