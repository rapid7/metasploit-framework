class Pry
  class Command::FindMethod < Pry::ClassCommand
    extend Pry::Helpers::BaseHelpers

    match 'find-method'
    group 'Context'
    description 'Recursively search for a method within a Class/Module or the current namespace.'
    command_options :shellwords => false

    banner <<-'BANNER'
      Usage: find-method  [-n|-c] METHOD [NAMESPACE]

      Recursively search for a method within a Class/Module or the current namespace.
      Use the `-n` switch (the default) to search for methods whose name matches the
      given regex. Use the `-c` switch to search for methods that contain the given
      code.

      # Find all methods whose name match /re/ inside
      # the Pry namespace. Matches Pry#repl, etc.
      find-method re Pry

      # Find all methods that contain the code:
      # output.puts inside the Pry namespace.
      find-method -c 'output.puts' Pry
    BANNER

    def options(opt)
      opt.on :n, :name,    "Search for a method by name"
      opt.on :c, :content, "Search for a method based on content in Regex form"
    end

    def process
      return if args.size < 1
      klass = search_class

      matches = if opts.content?
        content_search(klass)
      else
        name_search(klass)
      end

      show_search_results(matches)
    end

    private

    # @return [Regexp] The pattern to search for.
    def pattern
      @pattern ||= ::Regexp.new args[0]
    end

    # Output the result of the search.
    #
    # @param [Array] matches
    def show_search_results(matches)
      if matches.empty?
        output.puts text.bold("No Methods Matched")
      else
        print_matches(matches)
      end
    end

    # The class to search for methods.
    # We only search classes, so if the search object is an
    # instance, return its class. If no search object is given
    # search `target_self`.
    def search_class
      klass = if args[1]
                target.eval(args[1])
              else
                target_self
              end

      klass.is_a?(Module) ? klass : klass.class
    end

    # pretty-print a list of matching methods.
    #
    # @param [Array<Method>] matches
    def print_matches(matches)
      grouped = matches.group_by(&:owner)
      order = grouped.keys.sort_by{ |x| x.name || x.to_s }

      order.each do |klass|
        print_matches_for_class(klass, grouped)
      end
    end

    # Print matched methods for a class
    def print_matches_for_class(klass, grouped)
      output.puts text.bold(klass.name)
      grouped[klass].each do |method|
        header = method.name_with_owner
        output.puts header + additional_info(header, method)
      end
    end

    # Return the matched lines of method source if `-c` is given or ""
    # if `-c` was not given
    def additional_info(header, method)
      if opts.content?
        ": " << colorize_code(matched_method_lines(header, method))
      else
        ""
      end
    end

    def matched_method_lines(header, method)
      method.source.split(/\n/).select {|x| x =~ pattern }.join("\n#{' ' * header.length}")
    end

    # Run the given block against every constant in the provided namespace.
    #
    # @param [Module] klass The namespace in which to start the search.
    # @param [Hash<Module,Boolean>] done The namespaces we've already visited (private)
    # @yieldparam klass Each class/module in the namespace.
    #
    def recurse_namespace(klass, done={}, &block)
      return if !(Module === klass) || done[klass]

      done[klass] = true

      yield klass

      klass.constants.each do |name|
        next if klass.autoload?(name)
        begin
          const = klass.const_get(name)
        rescue RescuableException
          # constant loading is an inexact science at the best of times,
          # this often happens when a constant was .autoload? but someone
          # tried to load it. It's now not .autoload? but will still raise
          # a NameError when you access it.
        else
          recurse_namespace(const, done, &block)
        end
      end
    end

    # Gather all the methods in a namespace that pass the given block.
    #
    # @param [Module] namespace The namespace in which to search.
    # @yieldparam [Method] method The method to test
    # @yieldreturn [Boolean]
    # @return [Array<Method>]
    #
    def search_all_methods(namespace)
      done = Hash.new{ |h,k| h[k] = {} }
      matches = []

      recurse_namespace(namespace) do |klass|
        (Pry::Method.all_from_class(klass) + Pry::Method.all_from_obj(klass)).each do |method|
          next if done[method.owner][method.name]
          done[method.owner][method.name] = true

          matches << method if yield method
        end
      end

      matches
    end

    # Search for all methods with a name that matches the given regex
    # within a namespace.
    #
    # @param [Module] namespace The namespace to search
    # @return [Array<Method>]
    #
    def name_search(namespace)
      search_all_methods(namespace) do |meth|
        meth.name =~ pattern
      end
    end

    # Search for all methods who's implementation matches the given regex
    # within a namespace.
    #
    # @param [Module] namespace The namespace to search
    # @return [Array<Method>]
    #
    def content_search(namespace)
      search_all_methods(namespace) do |meth|
        begin
          meth.source =~ pattern
        rescue RescuableException
          false
        end
      end
    end
  end

  Pry::Commands.add_command(Pry::Command::FindMethod)
end
