# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          class EncapsulatedContentInfo < RASN1::Model

            sequence :encapsulated_content_info,
                     content: [objectid(:econtent_type),
                               octet_string(:econtent, explicit: 0, constructed: true, optional: true)
            ]

            def econtent
              if self[:econtent_type].value == '1.3.6.1.5.2.3.2'
                KdcDhKeyInfo.parse(self[:econtent].value)
              elsif self[:econtent_type].value == '1.3.6.1.5.2.3.1'
                AuthPack.parse(self[:econtent].value)
              end
            end
          end
        end
      end
    end
  end
end
