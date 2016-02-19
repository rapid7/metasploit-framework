# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module CredentialCache
        class Element

          def self.attr_accessor(*vars)
            @attributes ||= []
            @attributes.concat vars
            super(*vars)
          end

          # Retrieves the element class fields
          #
          # @return [Array]
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

          # Retrieves the element instance fields
          #
          # @return [Array]
          def attributes
            self.class.attributes
          end

          # Encodes the Rex::Proto::Kerberos::CredentialCache::Element into an String. This
          # method has been designed to be overridden by subclasses.
          #
          # @raise [NoMethodError]
          def encode
            raise ::NoMethodError, 'Method designed to be overridden'
          end
        end
      end
    end
  end
end