module Metasploit
  module Framework
    module NTDS
      require 'metasploit/framework/ntds/account'
      # This class respresent an NTDS parser. It interacts with the Meterpreter Client
      # to provide a simple interface for enumerating AD user accounts.
      class Parser

        # The size, in bytes, of an NTDS account object
        ACCOUNT_SIZE = 3948
        # The size, in Bytes, of a batch of NTDS accounts
        BATCH_SIZE = 78960

        # @!attribute channel
        #   @return [Rex::Post::Meterpreter::Channels::Pool] The Meterpreter NTDS Parser Channel
        attr_accessor :channel
        # @!attribute client
        #   @return [Msf::Session] The Meterpreter Client
        attr_accessor :client
        # @!attribute file_path
        #   @return [String] The path to the NTDS.dit file on the remote system
        attr_accessor :file_path

        def initialize(client, file_path='')
          raise ArgumentError, "Invalid Filepath" unless file_path.present?
          @file_path = file_path
          @channel = client.priv.ntds_parse(file_path)
          @client = client
        end

        # Yields a [Metasploit::Framework::NTDS::Account] for each account found
        # in the remote NTDS.dit file.
        #
        # @yieldparam account [Metasploit::Framework::NTDS::Account] an AD user account
        # @return [void] does not return a value
         def each_account
           raw_batch_data = pull_batch
           until raw_batch_data.nil?
             batch = raw_batch_data.dup
             while batch.present?
               raw_data = batch.slice!(0,ACCOUNT_SIZE)
               # Make sure our data isn't all Null-bytes
               if raw_data.match(/[^\x00]/)
                 account = Metasploit::Framework::NTDS::Account.new(raw_data)
                 yield account
               end
             end
             raw_batch_data = pull_batch
           end
           channel.close
         end

        private

        def pull_batch
          if channel.cid.nil?
            reopen_channel
          end
          begin
            raw_batch_data = channel.read(BATCH_SIZE)
          rescue EOFError
            raw_batch_data = nil
          end
          raw_batch_data
        end

        def reopen_channel
          @channel = client.priv.ntds_parse(file_path)
        end

      end
    end
  end
end