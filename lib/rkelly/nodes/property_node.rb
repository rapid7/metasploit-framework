module RKelly
  module Nodes
    class PropertyNode < Node
      attr_reader :name
      def initialize(name, value)
        super(value)
        @name = name
      end
    end

    %w[Getter Setter].each {|node| eval "class #{node}PropertyNode < PropertyNode; end"}
  end
end
