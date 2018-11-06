module RubySMB
  module Dcerpc
    # The Response PDU as defined in
    # [The response PDU](http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_04_10)
    class Response < BinData::Record
      endian :little

      pdu_header :pdu_header, label: 'PDU header'

      uint32 :alloc_hint,    label: 'Allocation hint',  initial_value: -> { stub.do_num_bytes }
      uint16 :p_cont_id,     label: 'Presentation context identification'
      uint8  :cancel_count,  label: 'Cancel count'
      uint8  :reserved

      string :stub,          label: 'Stub', read_length: -> { pdu_header.frag_length - stub.abs_offset - pdu_header.auth_length }

      string :auth_verifier, label: 'Authentication verifier',
        onlyif: -> { pdu_header.auth_length > 0 },
        read_length: -> { pdu_header.auth_length }

      def initialize_instance
        super
        pdu_header.ptype = RubySMB::Dcerpc::PTypes::RESPONSE
      end
    end
  end
end
