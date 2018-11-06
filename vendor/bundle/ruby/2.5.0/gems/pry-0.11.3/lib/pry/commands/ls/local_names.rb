class Pry
  class Command::Ls < Pry::ClassCommand
    class LocalNames < Pry::Command::Ls::Formatter

      def initialize(no_user_opts, args, _pry_)
        super(_pry_)
        @no_user_opts = no_user_opts
        @args = args
        @sticky_locals = _pry_.sticky_locals
      end

      def correct_opts?
        super || (@no_user_opts && @args.empty?)
      end

      def output_self
        local_vars = grep.regexp[@target.eval('local_variables')]
        output_section('locals', format(local_vars))
      end

      private

      def format(locals)
        locals.sort_by(&:downcase).map do |name|
          if @sticky_locals.include?(name.to_sym)
            color(:pry_var, name)
          else
            color(:local_var, name)
          end
        end
      end

    end
  end
end
