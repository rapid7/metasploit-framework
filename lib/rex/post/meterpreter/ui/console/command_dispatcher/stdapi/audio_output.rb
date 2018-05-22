# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'bindata'

module Rex
  module Post
    module Meterpreter
      module Ui

        ###
        #
        # Play audio on remote system
        #
        ###
        class Console::CommandDispatcher::Stdapi::AudioOutput
          Klass = Console::CommandDispatcher::Stdapi::AudioOutput

          include Console::CommandDispatcher

          #
          # List of supported commands.
          #
          def commands
            all = {
              'play' => 'play an audio file on target system, nothing written on disk'
            }
            reqs = {
              'play'    => []
            }

            filter_commands(all, reqs)
          end

          #
          # Name for this dispatcher
          #
          def name
            "Stdapi: Audio Output"
          end

          def cmd_play(*args)
            audio_path = nil

            play_start_opts = Rex::Parser::Arguments.new(
              "-h" => [ false, "Help Banner" ],
              "-f" => [ true, "The audio file path (warning: will be copied to memory)" ]
            )

            play_start_opts.parse(args) do |opt, _idx, val|
              case opt
              when "-h"
                print_line("Usage: audio_play [options]\n")
                print_line("Upload file to targets memory and play it from memory")
                print_line(play_start_opts.usage)
                return
              when "-f"
                audio_path = val
              end
            end

            print_status("Playing #{audio_path}...")
            client.audio_output.play_file(audio_path)
            print_status("Done")
          end
        end
      end
    end
  end
end
