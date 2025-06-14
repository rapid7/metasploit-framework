# -*- coding: binary -*-
require 'rasn1'

module Rex::Proto::CryptoAsn1
  # see: [[MS-WCCE]: 2.2.2.7.10 szENROLLMENT_NAME_VALUE_PAIR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec)
  class EnrollmentNameValuePair < RASN1::Model
    sequence :enrollment_name_value_pair, content: [
      bmp_string(:name),
      bmp_string(:value)
    ]
  end

  # see: [[MS-WCCE]: 2.2.2.7.7.4 szOID_NTDS_CA_SECURITY_EXT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71)
  class NtdsCaSecurityExt < RASN1::Model
    class OtherName < RASN1::Model
      sequence :OtherName, implicit: 0, content: [
        objectid(:type_id),
        octet_string(:value, explicit: 0, constructed: true)
      ]
    end

    sequence :NtdsCaSecurityExt,
      constructed: true,
      content: [
        wrapper(model(:OtherName, OtherName))
      ]
  end
end
