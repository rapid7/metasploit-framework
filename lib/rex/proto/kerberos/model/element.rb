# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a principal, an asset (e.g., a
        # workstation user or a network server) on a network.
        class Element

          include Rex::Proto::Kerberos::Model

          def self.attr_accessor(*vars)
            @attributes ||= []
            @attributes.concat vars
            super(*vars)
          end

          def self.attributes
            @attributes
          end

          def self.decode(input)
            elem = self.new
            elem.decode(input)
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

          def decode(input)
            self
          end

          def encode
            ''
          end
        end
      end
    end
  end
end