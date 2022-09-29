# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        module Pkinit
          # This class is a representation of a ContentInfo
          class ContentInfo < RASN1::Model

            sequence :content_info,
                     content: [objectid(:content_type),
                               # In our case, expected to be SignedData
                               any(:signed_data)
  
            ]

            def signed_data
              if self[:content_type].value == '1.2.840.113549.1.7.2'
                SignedData.parse(self[:signed_data].value)
              end
            end
          end
        end
      end
    end
  end
end
