module RubySMB
  module Dcerpc
    # The common header fields for connection-oriented PDU's as defined in
    # [Connection-oriented PDU Data Types](http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03)
    class PDUHeader < BinData::Record
      endian :little

      uint8 :rpc_vers,       label: 'RPC version', initial_value: 5
      uint8 :rpc_vers_minor, label: 'Minor version'
      uint8 :ptype,          label: 'PDU type'

      struct :pfc_flags do
        bit1  :object_uuid,     label: 'Object UUID'
        bit1  :maybe,           label: 'Maybe call semantics'
        bit1  :did_not_execute, label: 'Did not execute'
        bit1  :conc_mpx,        label: 'Concurrent multiplexing'
        bit1  :reserved_1,      label: 'Reserved'
        bit1  :pending_cancel,  label: 'Pending cancel'
        bit1  :last_frag,       label: 'Last fragment',  initial_value: 1
        bit1  :first_frag,      label: 'First fragment', initial_value: 1
      end

      uint32 :packed_drep, label: 'NDR data representation format label', initial_value: 0x10
      uint16 :frag_length, label: 'Total length of fragment',             initial_value: -> { parent.do_num_bytes }
      uint16 :auth_length, label: 'Length of auth_value'
      uint32 :call_id,     label: 'Call identifier',                      initial_value: 1
    end
  end
end
