# frozen_string_literal: true
module YARD
  module Serializers
    # Serializes an object to a process (like less)
    #
    # @example Serializing to a pager (less)
    #   serializer = ProcessSerializer.new('less')
    #   serializer.serialize(object, "data!")
    class ProcessSerializer < Base
      # Creates a new ProcessSerializer for the shell command +cmd+
      #
      # @param [String] cmd the command that will accept data on stdin
      def initialize(cmd)
        @cmd = cmd
      end

      # Overrides serialize behaviour and writes data to standard input
      # of the associated command
      def serialize(_object, data)
        IO.popen(@cmd, 'w') {|io| io.write(data) }
      end
    end
  end
end
