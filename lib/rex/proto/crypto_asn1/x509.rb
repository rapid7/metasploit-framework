# -*- coding: binary -*-
require 'rasn1'
require 'rex/proto/crypto_asn1/types'

module Rex::Proto::CryptoAsn1::X509
  class X121Address < RASN1::Model
    numeric_string :X121Address
  end

  class NetworkAddress < X121Address
    root_options implicit: 0
  end

  class TerminalIdentifier < RASN1::Model
    printable_string :TerminalIdentifier, implicit: 1
  end

  class AdministrationDomainName < RASN1::Model
    choice :AdministrationDomainName, class: :application, explicit: 2, content: [
      numeric_string(:numeric),
      printable_string(:printable)
    ]
  end

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

  class CountryName < RASN1::Model
    choice :CountryName, class: :application, explicit: 1, content: [
      numeric_string(:x121_dcc_code),
      printable_string(:iso_3166_alpha2_code)
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

  class ExtensionAttribute < RASN1::Model
    sequence :ExtensionAttribute, content: [
      integer(:extension_attribute_type, implicit: 0),
      any(:extension_attribute_value, implicit: 1)
    ]
  end

  class ExtensionAttributes < RASN1::Model
    set_of(:ExtensionAttributes, ExtensionAttribute)
  end

  class NumericUserIdentifier < RASN1::Model
    numeric_string :NumericUserIdentifier, implicit: 4
  end

  class OrganizationName < RASN1::Model
    printable_string :OrganizationName, implicit: 3
  end

  class OrganizationalUnitName < RASN1::Types::PrintableString
  end

  class OrganizationalUnitNames < RASN1::Model
    sequence_of(:OrganizationalUnitNames, OrganizationalUnitName)
  end

  class PersonalName < RASN1::Model
    set :PersonalName, content: [
      printable_string(:surname, implicit: 0),
      printable_string(:given_name, implicit: 1),
      printable_string(:initials, implicit: 2),
      printable_string(:generation_qualifier, implicit: 3)
    ]
  end

  class PrivateDomainName < RASN1::Model
    choice :PrivateDomainName, content: [
      numeric_string(:numeric),
      printable_string(:printable)
    ]
  end

  class BuiltinDomainDefinedAttribute < RASN1::Model
    sequence :BuiltinDomainDefinedAttribute, content: [
      printable_string(:type),
      printable_string(:value)
    ]
  end

  class BuiltInDomainDefinedAttributes < RASN1::Model
    sequence_of(:BuiltInDomainDefinedAttributes, BuiltinDomainDefinedAttribute)
  end

  class BuiltInStandardAttributes < RASN1::Model
    sequence :BuiltInStandardAttributes, content: [
      wrapper(model(:country_name, CountryName), explicit: 0, class: :application, optional: true),
      wrapper(model(:administration_domain_name, AdministrationDomainName), explicit: 1, class: :application, optional: true),
      wrapper(model(:network_address, NetworkAddress), implicit: 0, optional: true),
      wrapper(model(:terminal_identifier, TerminalIdentifier), implicit: 1, optional: false),
      wrapper(model(:private_domain_name, PrivateDomainName), implicit: 2, optional: true),
      wrapper(model(:organization_name, OrganizationName), implicit: 3, optional: true),
      wrapper(model(:numeric_user_identifier, NumericUserIdentifier), implicit: 4, optional: true),
      wrapper(model(:personal_name, PersonalName), implicit: 5, optional: true),
      wrapper(model(:organizational_unit_names, OrganizationalUnitNames), implicit: 6, optional: true)
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

  class ORAddress < RASN1::Model
    sequence :ORAddress, implicit: 3, content: [
      wrapper(model(:built_in_standard_attributes, BuiltInStandardAttributes)),
      wrapper(model(:built_in_domain_defined_attributes, BuiltInDomainDefinedAttributes), optional: true),
      wrapper(model(:extension_attributes, ExtensionAttributes), optional: true)
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
      wrapper(model(:x400Address, ORAddress), implicit: 3),
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
