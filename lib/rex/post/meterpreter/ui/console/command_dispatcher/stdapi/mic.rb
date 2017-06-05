class Mic
end# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'bindata'

module Rex
  module Post
    module Meterpreter
      module Ui

        ###
        #
        # Mic - Capture audio from the remote system
        #
        ###
        class Console::CommandDispatcher::Stdapi::Mic
          Klass = Console::CommandDispatcher::Stdapi::Mic

          include Console::CommandDispatcher

          #
          # List of supported commands.
          #
          def commands
            {
                'mic_start'             => 'play an audio stream from the specified mic',
                'mic_stop'              => 'stop capturing audio from device',
                'list_audio_interfaces' => 'list all audio interfaces',
                'listen'                => 'listen to audio via audio player'
            }
          end

          #
          # Name for this dispatcher
          #
          def name
            "Stdapi: Mic"
          end

          def cmd_list_audio_interfaces
            client.mic.mic_list
            if client.mic.mic_list.length == 0
              print_error("No mics were found")
              return
            end

            client.mic.mic_list.each_with_index do |name, indx|
              print_line("#{indx + 1}: #{name}")
            end
          end

          def cmd_mic_start(index=0, start_delay=4096, play_audio=true)
            print_status("Streaming mic audio channel...")

            if client.mic.mic_list.length == 0
              print_error("Target does not have a mic")
              return
            end

            print_status("Starting...")
            stream_path = Rex::Text.rand_text_alpha(8) + ".wav"
            duration = 1800
            quality  = 50

            print_status("Audio File: #{stream_path}")
            print_status("Streaming...")

            client.mic.stream
          end

          def cmd_mic_stop(index=0)
            client.mic.mic_stop(index)
          end

          def cmd_listen(stream_path)
            Rex::Compat.open_webrtc_browser("file://#{::File.absolute_path(stream_path)}")
          end
        end
      end
    end
  end
end
