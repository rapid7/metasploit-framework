# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        class Element

          include Rex::Proto::Kerberos::Pac

          def self.attr_accessor(*vars)
            @attributes ||= []
            @attributes.concat vars
            super(*vars)
          end

          def self.attributes
            @attributes
          end

          def initialize(options = {})
            self.class.attributes.each do |attr|
              if options.has_key?(attr)
                m = (attr.to_s + '=').to_sym
                self.send(m, options[attr])
              end
            end
          end

          def attributes
            self.class.attributes
          end

          def encode
            ''
          end
        end
      end
    end
  end
end