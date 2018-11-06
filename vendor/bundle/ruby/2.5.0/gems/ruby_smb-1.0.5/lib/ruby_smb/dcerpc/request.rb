module RubySMB
  module Dcerpc
    # The Request PDU as defined in
    # [The request PDU](http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_04_09)
    class Request < BinData::Record
      endian :little

      pdu_header :pdu_header, label: 'PDU header'

      uint32 :alloc_hint,     label: 'Allocation hint',  initial_value: -> { stub.do_num_bytes }
      uint16 :p_cont_id,      label: 'Presentation context identification'
      uint16 :opnum,          label: 'Operation Number'

      uuid   :object,         label: 'Object UID',      onlyif: -> { pdu_header.pfc_flags.object_uuid == 1 }

      choice :stub, label: 'Stub', selection: -> { opnum } do
        net_share_enum_all RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL, host: -> { host }
      end

      string :auth_verifier, label: 'Authentication verifier',
        onlyif: -> { pdu_header.auth_length > 0 },
        read_length: -> { pdu_header.auth_length }

      def initialize_instance
        super
        pdu_header.ptype = RubySMB::Dcerpc::PTypes::REQUEST
      end
    end
  end
end
