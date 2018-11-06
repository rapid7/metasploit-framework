require 'pry/commands/ls/interrogatable'
require 'pry/commands/ls/methods_helper'

class Pry
  class Command::Ls < Pry::ClassCommand
    class SelfMethods < Pry::Command::Ls::Formatter
      include Pry::Command::Ls::Interrogatable
      include Pry::Command::Ls::MethodsHelper

      def initialize(interrogatee, no_user_opts, opts, _pry_)
        super(_pry_)
        @interrogatee = interrogatee
        @no_user_opts = no_user_opts
        @ppp_switch = opts[:ppp]
        @jruby_switch = opts['all-java']
      end

      def output_self
        methods = all_methods(true).select do |m|
          m.owner == @interrogatee && grep.regexp[m.name]
        end
        heading = "#{ Pry::WrappedModule.new(@interrogatee).method_prefix }methods"
        output_section(heading, format(methods))
      end

      private

      def correct_opts?
        @no_user_opts && interrogating_a_module?
      end

    end
  end
end
