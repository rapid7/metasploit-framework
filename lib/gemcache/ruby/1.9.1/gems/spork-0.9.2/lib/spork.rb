$LOAD_PATH.unshift(File.expand_path(File.dirname(__FILE__))) unless $LOAD_PATH.include?(File.expand_path(File.dirname(__FILE__)))
require 'pathname'
module Spork
  BINARY = File.expand_path(File.dirname(__FILE__) + '/../bin/spork')
  LIBDIR = Pathname.new(File.expand_path(File.dirname(__FILE__)))

  autoload :Server,        (LIBDIR + 'spork/server').to_s
  autoload :TestFramework, (LIBDIR + 'spork/test_framework').to_s
  autoload :AppFramework,  (LIBDIR + 'spork/app_framework').to_s
  autoload :RunStrategy,   (LIBDIR + 'spork/run_strategy').to_s
  autoload :Runner,        (LIBDIR + 'spork/runner').to_s
  autoload :Forker,        (LIBDIR + 'spork/forker').to_s
  autoload :Diagnoser,     (LIBDIR + 'spork/diagnoser').to_s
  autoload :GemHelpers,    (LIBDIR + 'spork/gem_helpers').to_s

  class << self
    # Run a block, during prefork mode.  By default, if prefork is called twice in the same file and line number, the supplied block will only be ran once.
    #
    # == Parameters
    #
    # * +prevent_double_run+ - Pass false to disable double run prevention
    def prefork(prevent_double_run = true, &block)
      return if prevent_double_run && already_ran?(caller.first)
      yield
    end
    
    # Run a block AFTER the fork occurs.  By default, if prefork is called twice in the same file and line number, the supplied block will only be ran once.
    #
    # == Parameters
    #
    # * +prevent_double_run+ - Pass false to disable double run prevention
    def each_run(prevent_double_run = true, &block)
      return if prevent_double_run && already_ran?(caller.first)
      if state == :prefork
        each_run_procs << block
      else
        yield
      end
    end
    
    # Run a block after specs are run.
    #
    # == Parameters
    #
    # * +prevent_double_run+ - Pass false to disable double run prevention
    def after_each_run(prevent_double_run = true, &block)
      return if prevent_double_run && already_ran?(caller.first)
      after_each_run_procs << block
    end

    def using_spork?
      state != :not_using_spork
    end

    def state
      @state ||= :not_using_spork
    end
    
    # Used by the server.  Called when loading the prefork blocks of the code.
    def exec_prefork(&block)
      @state = :prefork
      yield
    end
    
    # Used by the server.  Called to run all of the prefork blocks.
    def exec_each_run(&block)
      @state = :run
      activate_after_each_run_at_exit_hook
      each_run_procs.each { |p| p.call }
      each_run_procs.clear
      yield if block_given?
    end
    
    # Used by the server.  Called to run all of the after_each_run blocks.
    def exec_after_each_run
      # processes in reverse order similar to at_exit
      while p = after_each_run_procs.pop; p.call; end
      true
    end

    # Traps an instance method of a class (or module) so any calls to it don't actually run until Spork.exec_each_run
    def trap_method(klass, method_name)
      method_name_without_spork, method_name_with_spork = alias_method_names(method_name, :spork)
      
      klass.class_eval <<-EOF, __FILE__, __LINE__ + 1
        alias :#{method_name_without_spork} :#{method_name} unless method_defined?(:#{method_name_without_spork}) 
        def #{method_name}(*args, &block)
          Spork.each_run(false) do
            #{method_name_without_spork}(*args, &block)
          end
        end
      EOF
    end
    
    # Same as trap_method, but for class methods instead
    def trap_class_method(klass, method_name)
      trap_method((class << klass; self; end), method_name)
    end
    
    def detect_and_require(subfolder)
      ([LIBDIR.to_s] + other_spork_gem_load_paths).uniq.each do |gem_path|
        Dir.glob(File.join(gem_path, subfolder)).each { |file| require file }
      end
    end

    # This method is used to auto-discover peer plugins such as spork-testunit.
    def other_spork_gem_load_paths
      @other_spork_gem_load_paths ||= Spork::GemHelpers.latest_load_paths.grep(/spork/).select do |g|
        not g.match(%r{/spork-[0-9\-.]+/lib}) # don't include other versions of spork
      end
    end

    private
      def activate_after_each_run_at_exit_hook
        Kernel.module_eval do
          def at_exit(&block)
            Spork.after_each_run(false, &block)
          end
        end
      end

      def alias_method_names(method_name, feature)
        /^(.+?)([\?\!]{0,1})$/.match(method_name.to_s)
        ["#{$1}_without_spork#{$2}", "#{$1}_with_spork#{$2}"]
      end
      
      def already_ran
        @already_ran ||= []
      end
      
      def expanded_caller(caller_line)
        file, line = caller_line.split(/:(\d+)/)
        line.gsub(/:.+/, '')
        expanded = File.expand_path(file, Dir.pwd) + ":" + line
        if ENV['OS'] == 'Windows_NT' # windows
          expanded = expanded[2..-1]
        end
        expanded
      end
      
      def already_ran?(caller_script_and_line)
        return true if already_ran.include?(expanded_caller(caller_script_and_line))
        already_ran << expanded_caller(caller_script_and_line)
        false
      end
      
      def each_run_procs
        @each_run_procs ||= []
      end

      def after_each_run_procs
        @after_each_run_procs ||= []
      end
  end
end
