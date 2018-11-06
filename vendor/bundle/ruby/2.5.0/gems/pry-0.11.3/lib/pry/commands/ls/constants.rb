require 'pry/commands/ls/interrogatable'

class Pry
  class Command::Ls < Pry::ClassCommand
    class Constants < Pry::Command::Ls::Formatter
      DEPRECATED_CONSTANTS = [:Fixnum, :Bignum, :TimeoutError, :NIL, :FALSE, :TRUE]
      DEPRECATED_CONSTANTS << :JavaPackageModuleTemplate if Pry::Helpers::BaseHelpers.jruby?
      include Pry::Command::Ls::Interrogatable

      def initialize(interrogatee, no_user_opts, opts, _pry_)
        super(_pry_)
        @interrogatee = interrogatee
        @no_user_opts = no_user_opts
        @default_switch = opts[:constants]
        @verbose_switch = opts[:verbose]
        @dconstants = opts.dconstants?
      end

      def correct_opts?
        super || (@no_user_opts && interrogating_a_module?)
      end

      def output_self
        mod = interrogatee_mod
        constants = WrappedModule.new(mod).constants(@verbose_switch)
        output_section('constants', grep.regexp[format(mod, constants)])
      end

      private

      def show_deprecated_constants?
        @dconstants == true
      end

      def format(mod, constants)
        constants.sort_by(&:downcase).map do |name|
          if Object.respond_to?(:deprecate_constant) and
            DEPRECATED_CONSTANTS.include?(name)      and
            !show_deprecated_constants?
            next
          end
          if const = (!mod.autoload?(name) && (mod.const_get(name) || true) rescue nil)
            if (const < Exception rescue false)
              color(:exception_constant, name)
            elsif (Module === mod.const_get(name) rescue false)
              color(:class_constant, name)
            else
              color(:constant, name)
            end
          else
            color(:unloaded_constant, name)
          end
        end
      end

    end
  end
end
