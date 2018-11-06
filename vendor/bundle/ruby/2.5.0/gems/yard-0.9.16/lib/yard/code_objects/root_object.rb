# frozen_string_literal: true
module YARD
  module CodeObjects
    # Represents the root namespace object (the invisible Ruby module that
    # holds all top level modules, class and other objects).
    class RootObject < ModuleObject
      def path; @path ||= "" end
      def inspect; @inspect ||= "#<yardoc root>" end
      def root?; true end
      def title; 'Top Level Namespace' end

      def equal?(other)
        other == :root ? true : super(other)
      end

      def hash; :root.hash end
    end
  end
end
