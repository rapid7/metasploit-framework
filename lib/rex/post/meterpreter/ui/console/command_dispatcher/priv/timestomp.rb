# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
  module Post
    module Meterpreter
      module Ui
        ###
        #
        # This class provides commands that interact with the timestomp feature set of
        # the privilege escalation extension.
        #
        ###
        class Console::CommandDispatcher::Priv::Timestomp
          Klass = Console::CommandDispatcher::Priv::Timestomp

          include Console::CommandDispatcher

          @@timestomp_opts = Rex::Parser::Arguments.new(
            "-m" => [ true,  "Set the \"last written\" time of the file" ],
            "-a" => [ true,  "Set the \"last accessed\" time of the file" ],
            "-c" => [ true,  "Set the \"creation\" time of the file" ],
            "-e" => [ true,  "Set the \"mft entry modified\" time of the file" ],
            "-z" => [ true,  "Set all four attributes (MACE) of the file" ],
            "-f" => [ true,  "Set the MACE of attributes equal to the supplied file" ],
            "-b" => [ false, "Set the MACE timestamps so that EnCase shows blanks" ],
            "-r" => [ false, "Set the MACE timestamps recursively on a directory" ],
            "-v" => [ false, "Display the UTC MACE values of the file" ],
            "-h" => [ false, "Help banner" ]
          )

          #
          # List of supported commands.
          #
          def commands
            {
              "timestomp" => "Manipulate file MACE attributes"
            }
          end

          #
          # Name for this dispatcher.
          #
          def name
            "Priv: Timestomp"
          end

          #
          # This command provides the same level of features that vinnie's command
          # line timestomp interface provides with a similar argument set.
          #
          def cmd_timestomp(*args)
            paths = []

            modified  = nil
            accessed  = nil
            creation  = nil
            emodified = nil

            blank_file_mace = false
            blank_directory_mace = false
            get_file_mace = false
            help = false

            @@timestomp_opts.parse(args) do |opt, _idx, val|
              case opt
              when "-m"
                modified  = str_to_time(val)
              when "-a"
                accessed  = str_to_time(val)
              when "-c"
                creation  = str_to_time(val)
              when "-e"
                emodified = str_to_time(val)
              when "-z"
                modified  = str_to_time(val)
                accessed  = str_to_time(val)
                creation  = str_to_time(val)
                emodified = str_to_time(val)
              when "-f"
                print_status("Pulling MACE attributes from #{val}")
                hash = client.priv.fs.get_file_mace(val)
                if hash
                  modified = hash['Modified']
                  accessed = hash['Accessed']
                  creation = hash['Created']
                  emodified = hash['Entry Modified']
                end
              when "-b"
                blank_file_mace = true
              when "-r"
                blank_directory_mace = true
              when "-v"
                get_file_mace = true
              when "-h"
                help = true
              when nil
                paths << val
              end
            end

            if paths.empty?
              print_line("\nNo paths specified.")
              return nil
            end

            if !(modified || accessed || creation || emodified ||
                 blank_file_mace || blank_directory_mace || get_file_mace) || help
              print_line("\nUsage: timestomp <file(s)> OPTIONS\n" +
                @@timestomp_opts.usage)
              return nil
            end

            paths.uniq.each do |path|

              # If any one of the four times were specified, change them.
              if modified || accessed || creation || emodified
                print_status("Setting specific MACE attributes on #{path}")
                client.priv.fs.set_file_mace(path, modified, accessed, creation, emodified)
              end

              if blank_file_mace
                print_status("Blanking file MACE attributes on #{path}")
                client.priv.fs.blank_file_mace(path)
              end

              if blank_directory_mace
                print_status("Blanking directory MACE attributes on #{path}")
                client.priv.fs.blank_directory_mace(path)
              end

              if get_file_mace
                hash = client.priv.fs.get_file_mace(path)
                print_status("Showing MACE attributes for #{path}")
                print_line("Modified      : #{hash['Modified']}")
                print_line("Accessed      : #{hash['Accessed']}")
                print_line("Created       : #{hash['Created']}")
                print_line("Entry Modified: #{hash['Entry Modified']}")
              end
            end
          end

          protected

          #
          # Converts a date/time in the form of MM/DD/YYYY HH24:MI:SS
          #
          def str_to_time(str) # :nodoc:
            unless str.nil?
              _r, mon, day, year, hour, min, sec =
                str.match("^(\\d+?)/(\\d+?)/(\\d+?) (\\d+?):(\\d+?):(\\d+?)$").to_a
            end

            if str.nil? || mon.nil?
              raise ArgumentError, "Invalid date format, expected MM/DD/YYYY HH24:MI:SS (got #{str})"
            end

            Time.mktime(year, mon, day, hour, min, sec, 0)
          end
        end
      end
    end
  end
end
