module RubySMB
  module Dcerpc
    # The Bind PDU as defined in
    # [The bind PDU](http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_04_03)
    class PContElemT < BinData::Record
      endian :little

      uint16 :p_cont_id,     label: 'Context ID'
      uint8 :n_transfer_syn, label: 'Number of transfer syntaxes', initial_value: 1
      uint8 :reserved
      p_syntax_id_t :abstract_syntax, label: 'Abstract syntax',
        uuid: ->      { endpoint::UUID },
        ver_major: -> { endpoint::VER_MAJOR },
        ver_minor: -> { endpoint::VER_MINOR }
      array :transfer_syntaxes, label: 'Transfer syntax', type: :p_syntax_id_t,
        initial_length: -> { n_transfer_syn },
        uuid: ->      { Ndr::UUID },
        ver_major: -> { Ndr::VER_MAJOR },
        ver_minor: -> { Ndr::VER_MINOR }
    end

    class PContListT < BinData::Record
      endian :little

      uint8 :n_context_elem, label: 'Number of context elements', initial_value: -> { 1 }
      uint8 :reserved
      uint16 :reserved2
      array :p_cont_elem, label: 'Presentation context elements', type: :p_cont_elem_t,
        initial_length: -> {n_context_elem},
        endpoint: -> {endpoint}
    end

    class Bind < BinData::Record
      endian :little

      pdu_header :pdu_header,        label: 'PDU header'

      uint16 :max_xmit_frag,         label: 'max transmit frag size',    initial_value: 0xFFFF
      uint16 :max_recv_frag,         label: 'max receive  frag size',    initial_value: 0xFFFF
      uint32 :assoc_group_id,        label: 'ncarnation of client-server assoc group'

      p_cont_list_t :p_context_list, label: 'Presentation context list', endpoint: -> { endpoint }
      string :auth_verifier,         label: 'Authentication verifier',
        onlyif: -> { pdu_header.auth_length > 0 },
        read_length: -> { pdu_header.auth_length }

      def initialize_instance
        super
        pdu_header.ptype = RubySMB::Dcerpc::PTypes::BIND
      end
    end
  end
end

