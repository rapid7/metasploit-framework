require 'rasn1'

module Rex::Proto::Gss
  # Initial negotiation token
  # https://datatracker.ietf.org/doc/html/rfc4178#section-4.2
  class MechType < RASN1::Types::ObjectId
  end

  class MechTypeList < RASN1::Model
    sequence_of(:mech_type, Rex::Proto::Gss::MechType)
  end

  class ContextFlags < RASN1::Types::BitString
    def initialize(options = {})
      options[:bit_length] = 32
      super
    end
  end

  class NegTokenInit < RASN1::Model
    sequence :neg_token_init, explicit: 0, class: :context, constructed: true,
             content: [wrapper(model(:mech_type_list, Rex::Proto::Gss::MechTypeList), explicit: 0, constructed: true),
                       wrapper(model(:context_flags, Rex::Proto::Gss::ContextFlags), explicit: 1, constructed: true, optional: true),
                       octet_string(:mech_token, explicit: 2, constructed: true, optional: true),
                       octet_string(:mech_list_mic, explicit: 3, optional: true)
             ]
  end

  class SpnegoNegTokenInit < RASN1::Model
    sequence :gssapi, implicit: 0, class: :application, constructed: true,
             content: [objectid(:oid),
                       model(:neg_token_init, Rex::Proto::Gss::NegTokenInit)]

    def mech_token
      self[:gssapi][:neg_token_init][:mech_token].value
    end

    def mech_type_list
      self[:gssapi][:neg_token_init][:mech_type_list][:mech_type]
    end
  end
end