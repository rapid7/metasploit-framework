# -*- coding: binary -*-

#
# Rex
#

require 'rex/ui/text/output/buffer/stdout'


module Msf
  module Ui
    module Console
      module CommandDispatcher

        #
        # {CommandDispatcher} for commands related to background jobs in Metasploit Framework.
        #
        class Resource

          include Msf::Ui::Console::CommandDispatcher


          def commands
            {
              "resource"   => "Run the commands stored in a file",
              "makerc"     => "Save commands entered since start to a file",
            }
          end

          #
          # Returns the name of the command dispatcher.
          #
          def name
            "Resource Script"
          end

          def cmd_resource_help
            print_line "Usage: resource path1 [path2 ...]"
            print_line
            print_line "Run the commands stored in the supplied files (- for stdin)."
            print_line "Resource files may also contain ERB or Ruby code between <ruby></ruby> tags."
            print_line
            print_line "See also: makerc"
            print_line
          end

          def cmd_resource(*args)
            if args.empty?
              cmd_resource_help
              return false
            end

            args.each do |res|
              res_expand = ::File.expand_path(res)
              good_res = nil
              if res == '-'
                good_res = res
              elsif ::File.file?(res_expand) && File.readable?(res_expand)
                good_res = res_expand
              else
                # let's check to see if it's in the scripts/resource dir (like when tab completed)
                [
                  ::Msf::Config.script_directory + ::File::SEPARATOR + 'resource',
                  ::Msf::Config.user_script_directory + ::File::SEPARATOR + 'resource'
                ].each do |dir|
                  res_path = dir + ::File::SEPARATOR + res
                  if ::File.file?(res_path) && File.readable?(res_path)
                    good_res = res_path
                    break
                  end
                end
              end
              if good_res
                driver.load_resource(good_res)
              else
                print_error("#{res} is not a valid resource file")
                next
              end
            end
          end

          #
          # Tab completion for the resource command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_resource_tabs(str, words)
            tabs = []
            #return tabs if words.length > 1
            if !str.nil? && (str.start_with?('~') || str =~ /^#{Regexp.escape(File::SEPARATOR)}/)
              # then you are probably specifying a full path so let's just use normal file completion
              return tab_complete_filenames(str, words)
            elsif (not words[1] or not words[1].match(/^\//))
              # then let's start tab completion in the scripts/resource directories
              begin
                [
                  ::Msf::Config.script_directory + File::SEPARATOR + "resource",
                  ::Msf::Config.user_script_directory + File::SEPARATOR + "resource",
                  '.'
                ].each do |dir|
                  next unless ::File.exist?(dir)
                  tabs += ::Dir.new(dir).find_all { |e|
                    path = dir + File::SEPARATOR + e
                    ::File.file?(path) && File.readable?(path)
                  }
                end
              rescue
              end
            else
              tabs += tab_complete_filenames(str,words)
            end
            return tabs
          end

          def cmd_makerc_help
            print_line "Usage: makerc <output rc file>"
            print_line
            print_line "Save the commands executed since startup to the specified file."
            print_line
          end

          def cmd_makerc_tabs(str, words)
            tab_complete_filenames(str, words)
          end

          #
          # Saves commands executed since the ui started to the specified msfrc file
          #
          def cmd_makerc(*args)
            if args.empty? || args.include?('-h')
              cmd_makerc_help
              return false
            end
            driver.save_recent_history(args[0])
          end
        end

      end
    end
  end
end
