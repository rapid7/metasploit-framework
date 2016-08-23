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
                'stdapi_sys_audio_get_interfaces' => 'list all audio interfaces',
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
              response, audio_channel = client.mic.mic_start
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

            print_status("Started")
          end
        end
      end
    end
  end
end
