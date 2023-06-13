# -*- coding: binary -*-
require 'rasn1'
require 'rex/proto/crypto_asn1/types'

module Rex::Proto::CryptoAsn1::X509
  class AttributeType < RASN1::Types::ObjectId
  end

  class AttributeValue < RASN1::Types::Any
  end

  class AttributeTypeAndValue < RASN1::Model
    sequence :AttributeTypeAndValue, content: [
      wrapper(model(:type, AttributeType)),
      wrapper(model(:value, AttributeValue))
    ]
  end

  class DirectoryString < RASN1::Model
    choice :DirectoryString, content: [
      teletex_string(:teletexString, strict_encoding: false),
      printable_string(:printableString),
      universal_string(:universalString),
      utf8_string(:utf8String),
      bmp_string(:bmpString)
    ]
  end

  class EDIPartyName < RASN1::Model
    sequence :EDIPartyName, content: [
      wrapper(model(:nameAssigner, DirectoryString), implicit: 0, optional: true),
      wrapper(model(:partyName, DirectoryString), implicit: 1)
    ]
  end

  class RelativeDistinguishedName < RASN1::Model
    set_of(:RelativeDistinguishedName, AttributeTypeAndValue)
  end

  class RDNSequence < RASN1::Model
    sequence_of(:RDNSequence, RelativeDistinguishedName)
  end

  class Name < RASN1::Model
    choice :Name, content: [
      wrapper(model(:RDNSequence, RDNSequence))
    ]
  end

  class OtherName < RASN1::Model
    sequence :OtherName, implicit: 0, content: [
      objectid(:type_id),
      any(:value, explicit: 0, constructed: true)
    ]
  end

  class GeneralName < RASN1::Model
    choice :GeneralName, content: [
      wrapper(model(:otherName, OtherName), implicit: 0),
      ia5_string(:rfc822Name, implicit: 1),
      ia5_string(:dNSName, implicit: 2),
      # wrapper(model(:x400Address, ORAddress), implicit: 3),
      wrapper(model(:directoryName, Name), implicit: 4),
      wrapper(model(:ediPartyName, EDIPartyName), implicit: 5),
      ia5_string(:uniformResourceIdentifier, implicit: 6),
      octet_string(:iPAddress, implicit: 7),
      objectid(:registeredID, implicit: 8)
    ]
  end

  # https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.1.7
  class GeneralNames < RASN1::Model
    sequence_of(:GeneralNames, GeneralName)
  end

  # https://datatracker.ietf.org/doc/html/rfc3280#section-4.2.1.7
  class SubjectAltName < GeneralNames
  end
end
