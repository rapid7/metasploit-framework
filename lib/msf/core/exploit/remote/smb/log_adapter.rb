# -*- coding: binary -*-

module Msf::Exploit::Remote::SMB::LogAdapter
  # API inherited from ::Rex::Ui::Output, but as it is a class - it can not be included as a mixin
  class Logger < ::Logger
    extend Forwardable

    def_delegators :@mod, :datastore, :print
    def_delegators :@mod, :vprint_bad, :vprint_error, :vprint_good, :vprint_line, :vprint_status, :vprint_warning
    def_delegators :@mod,  :print_bad,  :print_error,  :print_good,  :print_line,  :print_status,  :print_warning

    def initialize(mod, log_device)
      super(log_device)
      @mod = mod
    end
  end

  # Log devices to be used with Ruby's default Logging
  module LogDevice
    # Logs using the default framework logging mechanism
    class Framework
      def initialize(_framework)
        # Note that the framework instance is not technically required as {rlog} is global
        # it's just an attempt at future proofing the API
        # @framework = framework
      end

      def write(message)
        rlog(message)
      end

      def close
        # noop
      end
    end

    # Logs using the provided module
    class Module
      def initialize(mod)
        @mod = mod
      end

      def write(message)
        @mod.print(message)
      end

      def close
        # noop
      end
    end
  end
end
