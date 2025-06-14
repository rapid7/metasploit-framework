# -*- coding: binary -*-

module Msf
  module Sessions

    ###
    #
    # This class provides the ability to receive a custom stage callback
    #
    ###
    class Custom

      #
      # This interface supports basic interaction.
      #
      include Msf::Session
      include Msf::Session::Basic

      attr_accessor :arch
      attr_accessor :platform

      #
      # Returns the type of session.
      #
      def self.type
        "custom"
      end

      def initialize(rstream, opts = {})
        super
        self.platform ||= ""
        self.arch     ||= ""
        datastore = opts[:datastore]
      end

      def self.create_session(rstream, opts = {})
        Msf::Sessions::Custom.new(rstream, opts)
      end

      def process_autoruns(datastore)
        cleanup
      end

      def cleanup
        print_good("Custom stage sent; session has been closed")
        if rstream
          # this is also a best-effort
          rstream.close rescue nil
          rstream = nil
        end
      end

      #
      # Returns the session description.
      #
      def desc
        "Custom"
      end

      def self.can_cleanup_files
        false
      end

      #
      # Calls the class method
      #
      def type
        self.class.type
      end
    end
  end
end
