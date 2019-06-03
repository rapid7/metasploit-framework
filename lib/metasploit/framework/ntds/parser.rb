module Metasploit
  module Framework
    module NTDS
      require 'metasploit/framework/ntds/account'
      # This class respresent an NTDS parser. It interacts with the Meterpreter Client
      # to provide a simple interface for enumerating AD user accounts.
      class Parser

        # The size, in Bytes, of a batch of NTDS accounts
        BATCH_SIZE = (Metasploit::Framework::NTDS::Account::ACCOUNT_SIZE * 20)

        #@return [Rex::Post::Meterpreter::Channels::Pool] The Meterpreter NTDS Parser Channel
        attr_accessor :channel
        #@return [Msf::Session] The Meterpreter Client
        attr_accessor :client
        #@return [String] The path to the NTDS.dit file on the remote system
        attr_accessor :file_path

        def initialize(client, file_path='')
          raise ArgumentError, "Invalid Filepath" unless file_path.present?
          @file_path = file_path
          @channel = client.extapi.ntds.parse(file_path)
          @client = client
        end

        # Yields a [Metasploit::Framework::NTDS::Account] for each account found
        # in the remote NTDS.dit file.
        #
        # @yield [account]
        # @yieldparam account [Metasploit::Framework::NTDS::Account] an AD user account
        # @yieldreturn [void] does not return a value
         def each_account
           raw_batch_data = pull_batch
           until raw_batch_data.nil?
             batch = raw_batch_data.dup
             while batch.present?
               raw_data = batch.slice!(0,Metasploit::Framework::NTDS::Account::ACCOUNT_SIZE)
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
            dlog("NTDS Parser Channel was closed, reopening")
            reopen_channel
          end
          begin
            raw_batch_data = channel.read(BATCH_SIZE)
          rescue EOFError => e
            elog("NTDS Parser: Error pulling batch - #{e}")
            raw_batch_data = nil
          end
          raw_batch_data
        end

        def reopen_channel
          @channel = client.extapi.ntds.parse(file_path)
        end

      end
    end
  end
end
