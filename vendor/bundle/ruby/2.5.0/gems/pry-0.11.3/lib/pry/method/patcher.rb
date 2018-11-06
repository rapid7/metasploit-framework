class Pry
  class Method
    class Patcher
      attr_accessor :method

      @@source_cache = {}

      def initialize(method)
        @method = method
      end

      def self.code_for(filename)
        @@source_cache[filename]
      end

      # perform the patch
      def patch_in_ram(source)
        if method.alias?
          with_method_transaction do
            redefine source
          end
        else
          redefine source
        end
      end

      private

      def redefine(source)
        @@source_cache[cache_key] = source
        TOPLEVEL_BINDING.eval wrap(source), cache_key
      end

      def cache_key
        "pry-redefined(0x#{method.owner.object_id.to_s(16)}##{method.name})"
      end

      # Run some code ensuring that at the end target#meth_name will not have changed.
      #
      # When we're redefining aliased methods we will overwrite the method at the
      # unaliased name (so that super continues to work). By wrapping that code in a
      # transation we make that not happen, which means that alias_method_chains, etc.
      # continue to work.
      #
      def with_method_transaction
        temp_name = "__pry_#{method.original_name}__"
        method = self.method
        method.owner.class_eval do
          alias_method temp_name, method.original_name
          yield
          alias_method method.name, method.original_name
          alias_method method.original_name, temp_name
        end

      ensure
        method.send(:remove_method, temp_name) rescue nil
      end

      # Update the definition line so that it can be eval'd directly on the Method's
      # owner instead of from the original context.
      #
      # In particular this takes `def self.foo` and turns it into `def foo` so that we
      # don't end up creating the method on the singleton class of the singleton class
      # by accident.
      #
      # This is necessarily done by String manipulation because we can't find out what
      # syntax is needed for the argument list by ruby-level introspection.
      #
      # @param [String] line The original definition line. e.g. def self.foo(bar, baz=1)
      # @return [String]  The new definition line. e.g. def foo(bar, baz=1)
      def definition_for_owner(line)
        if line =~ /\Adef (?:.*?\.)?#{Regexp.escape(method.original_name)}(?=[\(\s;]|$)/
          "def #{method.original_name}#{$'}"
        else
          raise CommandError, "Could not find original `def #{method.original_name}` line to patch."
        end
      end

      # Apply wrap_for_owner and wrap_for_nesting successively to `source`
      # @param [String] source
      # @return [String] The wrapped source.
      def wrap(source)
        wrap_for_nesting(wrap_for_owner(source))
      end

      # Update the source code so that when it has the right owner when eval'd.
      #
      # This (combined with definition_for_owner) is backup for the case that
      # wrap_for_nesting fails, to ensure that the method will stil be defined in
      # the correct place.
      #
      # @param [String] source  The source to wrap
      # @return [String]
      def wrap_for_owner(source)
        Pry.current[:pry_owner] = method.owner
        owner_source = definition_for_owner(source)
        visibility_fix = "#{method.visibility.to_s} #{method.name.to_sym.inspect}"
        "Pry.current[:pry_owner].class_eval do; #{owner_source}\n#{visibility_fix}\nend"
      end

      # Update the new source code to have the correct Module.nesting.
      #
      # This method uses syntactic analysis of the original source file to determine
      # the new nesting, so that we can tell the difference between:
      #
      #   class A; def self.b; end; end
      #   class << A; def b; end; end
      #
      # The resulting code should be evaluated in the TOPLEVEL_BINDING.
      #
      # @param [String] source  The source to wrap.
      # @return [String]
      def wrap_for_nesting(source)
        nesting = Pry::Code.from_file(method.source_file).nesting_at(method.source_line)

        (nesting + [source] + nesting.map{ "end" } + [""]).join(";")
      rescue Pry::Indent::UnparseableNestingError
        source
      end
    end
  end
end
