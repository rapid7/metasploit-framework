module RKelly
  module Nodes
    class ForNode < Node
      attr_reader :init, :test, :counter
      def initialize(init, test, counter, body)
        super(body)
        @init = init
        @test = test
        @counter = counter
      end
    end
  end
end
