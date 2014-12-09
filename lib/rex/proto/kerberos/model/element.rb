module Rex
  module Proto
    module Kerberos
      module Model
        # This class provides a representation of a principal, an asset (e.g., a
        # workstation user or a network server) on a network.
        class Element
          include Rex::Proto::Kerberos::Model

          def self.decode(input)
            elem = self.new
            elem.decode(input)
          end

          def initialize

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