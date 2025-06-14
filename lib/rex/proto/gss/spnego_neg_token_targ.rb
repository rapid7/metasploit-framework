require 'rasn1'

module Rex::Proto::Gss
  # Negotiation token returned by the target to the initiator
  # https://www.rfc-editor.org/rfc/rfc2478
  class SpnegoNegTokenTarg < RASN1::Model
    ACCEPT_COMPLETED = 'accept-completed'
    ACCEPT_INCOMPLETE = 'accept-incomplete'
    REJECT = 'reject'
    REQUEST_MIC = 'request-mic'

    NEG_RESULTS = { ACCEPT_COMPLETED => 0,
                    ACCEPT_INCOMPLETE => 1,
                    REJECT => 2,
                    REQUEST_MIC => 3}

    sequence :token, explicit: 1, class: :context, constructed: true,
              content: [enumerated(:neg_result, enum: NEG_RESULTS, explicit: 0, class: :context, constructed: true, optional: true),
                        objectid(:supported_mech, explicit: 1, class: :context, constructed: true, optional: true),
                        octet_string(:response_token, explicit: 2, class: :context, constructed: true, optional: true),
                        octet_string(:mech_list_mic, explicit: 3, class: :context, constructed: true, optional: true)
    ]

    def neg_result
      self[:neg_result].value
    end

    def supported_mech
      self[:supported_mech].value
    end

    def response_token
      self[:response_token].value
    end

    def mech_list_mic
      self[:mech_list_mic].value
    end
  end
end