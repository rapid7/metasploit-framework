if RUBY_PLATFORM =~ /java/ && Gem::Version.new(JRUBY_VERSION) < Gem::Version.new('1.7.14')
  require 'java'

  # Re-implement methods on ruby's File that are buggy in JRuby so that the platform specific logic can be in this
  # module instead of everywhere these methods are used.
  module Metasploit::Model::File
    # On JRuby (< 1.7.14), File.realpath does not resolve symlinks, so need to drop to Java to get the real path.
    #
    # @param path [String] a path that may contain `'.'`, `'..'`, or symlinks
    # @return [String] canonical path
    # @see https://github.com/jruby/jruby/issues/538
    def self.realpath(path)
      file = java.io.File.new(path)

      file.canonical_path
    end

    class << self
      # Delegates to `::File` if `::File` supports the method when {Metasploit::Model::File} does not implement an
      # override to fix different platform incompatibilities.
      #
      # @param method_name [Symbol] name of method.
      # @param args [Array] arguments passed to method with name `method_name`.
      # @param block [Proc] block to pass after `args` to method with name `method_name`.
      def method_missing(method_name, *args, &block)
        if ::File.respond_to?(method_name)
          ::File.public_send(method_name, *args, &block)
        else
          super
        end
      end

      # Whether this module or `::File` responds to `method_name`.
      #
      # @param method_name [Symbol] name of method.
      # @param include_private [Boolean] whether to include private methods.
      # @return [Boolean]
      def respond_to?(method_name, include_private=false)
        ::File.respond_to?(method_name, include_private) || super
      end
    end
  end
else
  Metasploit::Model::File = ::File
end
