module Treetop
  module Compiler
    class LexicalAddressSpace
      def initialize
        reset_addresses
      end
      
      def next_address
        @next_address += 1
      end
      
      def reset_addresses
        @next_address = -1
      end
    end
  end
end