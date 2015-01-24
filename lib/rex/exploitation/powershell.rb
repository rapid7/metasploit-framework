# -*- coding: binary -*-

require 'rex/exploitation/powershell/output'
require 'rex/exploitation/powershell/parser'
require 'rex/exploitation/powershell/obfu'
require 'rex/exploitation/powershell/param'
require 'rex/exploitation/powershell/function'
require 'rex/exploitation/powershell/script'
require 'rex/exploitation/powershell/psh_methods'

module Rex
  module Exploitation
    module Powershell
      #
      # Reads script into a PowershellScript
      #
      # @param script_path [String] Path to the Script File
      #
      # @return [Script] Powershell Script object
      def self.read_script(script_path)
        Rex::Exploitation::Powershell::Script.new(script_path)
      end

      #
      # Insert substitutions into the powershell script
      # If script is a path to a file then read the file
      # otherwise treat it as the contents of a file
      #
      # @param script [String] Script file or path to script
      # @param subs [Array] Substitutions to insert
      #
      # @return [String] Modified script file
      def self.make_subs(script, subs)
        if ::File.file?(script)
          script = ::File.read(script)
        end

        subs.each do |set|
          script.gsub!(set[0], set[1])
        end

        script
      end

      #
      # Return an array of substitutions for use in make_subs
      #
      # @param subs [String] A ; seperated list of substitutions
      #
      # @return [Array] An array of substitutions
      def self.process_subs(subs)
        return [] if subs.nil? or subs.empty?
        new_subs = []
        subs.split(';').each do |set|
          new_subs << set.split(',', 2)
        end

        new_subs
      end
    end
  end
end
