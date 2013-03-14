# encoding: utf-8
module Mail
  module Encodings
    class TransferEncoding
      NAME = ''

      PRIORITY = -1

      def self.can_transport?(enc)
        enc = Encodings.get_name(enc)
        if Encodings.defined? enc
          Encodings.get_encoding(enc).new.is_a? self
        else
          false
        end
      end

      def self.can_encode?(enc)
        can_transport? enc 
      end

      def self.cost(str)
        raise "Unimplemented"
      end

      def self.to_s
        self::NAME
      end

      def self.get_best_compatible(source_encoding, str)
        if self.can_transport? source_encoding then
            source_encoding 
        else
            choices = []
            Encodings.get_all.each do |enc|
                choices << enc if self.can_transport? enc and enc.can_encode? source_encoding
            end
            best = nil 
            best_cost = 100
            choices.each do |enc|
                this_cost = enc.cost str
                if this_cost < best_cost then
                    best_cost = this_cost
                    best = enc
                elsif this_cost == best_cost then 
                    best = enc if enc::PRIORITY < best::PRIORITY
                end
            end
            best
        end
      end

      def to_s
        self.class.to_s
      end
    end
  end
end
