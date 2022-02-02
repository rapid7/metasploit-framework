module Metasploit
  module Framework
    module NTDS
      # This class represents an NTDS account structure as sent back by Meterpreter's
      # priv extension.
      class Account

        # Size of an NTDS Account Struct on the Wire
        ACCOUNT_SIZE = 3016
        # Size of a Date or Time Format String on the Wire
        DATE_TIME_STRING_SIZE = 30
        # Size of the AccountDescription Field
        DESCRIPTION_SIZE =1024
        # Size of a Hash History Record
        HASH_HISTORY_SIZE = 792
        # Size of a Hash String
        HASH_SIZE = 33
        # Size of the samAccountName field
        NAME_SIZE = 128

        #@return [String] The AD Account Description
        attr_accessor :description
        #@return [Boolean] If the AD account is disabled
        attr_accessor :disabled
        #@return [Boolean] If the AD account password is expired
        attr_accessor :expired
        #@return [String] Human Readable Date for the account's password expiration
        attr_accessor :expiry_date
        #@return [String] The LM Hash of the current password
        attr_accessor :lm_hash
        #@return [Array<String>] The LM hashes for previous passwords, up to 24
        attr_accessor :lm_history
        #@return [Integer] The count of historical LM hashes
        attr_accessor :lm_history_count
        #@return [Boolean] If the AD account is locked
        attr_accessor :locked
        #@return [Integer] The number of times this account has logged in
        attr_accessor :logon_count
        #@return [String] Human Readable Date for the last time the account logged in
        attr_accessor :logon_date
        #@return [String] Human Readable Time for the last time the account logged in
        attr_accessor :logon_time
        #@return [String] The samAccountName of the account
        attr_accessor :name
        #@return [Boolean] If the AD account password does not expire
        attr_accessor :no_expire
        #@return [Boolean] If the AD account does not require a password
        attr_accessor :no_pass
        #@return [String] The NT Hash of the current password
        attr_accessor :nt_hash
        #@return [Array<String>] The NT hashes for previous passwords, up to 24
        attr_accessor :nt_history
        #@return [Integer] The count of historical NT hashes
        attr_accessor :nt_history_count
        #@return [String] Human Readable Date for the last password change
        attr_accessor :pass_date
        #@return [String] Human Readable Time for the last password change
        attr_accessor :pass_time
        #@return [Integer] The Relative ID of the account
        attr_accessor :rid
        #@return [String] Byte String for the Account's SID
        attr_accessor :sid

        # @param raw_data [String] the raw 3948 byte string from the wire
        # @raise [ArgumentErrror] if a 3948 byte string is not supplied
        def initialize(raw_data)
          raise ArgumentError, "No Data Supplied" unless raw_data.present?
          raise ArgumentError, "Invalid Data" unless raw_data.length == ACCOUNT_SIZE
          data = raw_data.dup
          @name = get_string(data,NAME_SIZE)
          @description = get_string(data,DESCRIPTION_SIZE)
          @rid = get_int(data)
          @disabled = get_boolean(data)
          @locked = get_boolean(data)
          @no_pass = get_boolean(data)
          @no_expire = get_boolean(data)
          @expired = get_boolean(data)
          @logon_count = get_int(data)
          @nt_history_count = get_int(data)
          @lm_history_count = get_int(data)
          @expiry_date = get_string(data,DATE_TIME_STRING_SIZE)
          @logon_date =  get_string(data,DATE_TIME_STRING_SIZE)
          @logon_time = get_string(data,DATE_TIME_STRING_SIZE)
          @pass_date = get_string(data,DATE_TIME_STRING_SIZE)
          @pass_time = get_string(data,DATE_TIME_STRING_SIZE)
          @lm_hash = get_string(data,HASH_SIZE)
          @nt_hash = get_string(data,HASH_SIZE)
          @lm_history = get_hash_history(data)
          @nt_history = get_hash_history(data)
          @sid = data
        end

        # @return [String] String representation of the account data
        def to_s
          <<-EOS.strip_heredoc
          #{@name} (#{@description})
          #{@name}:#{@rid}:#{ntlm_hash}
          Password Expires: #{@expiry_date}
          Last Password Change: #{@pass_time} #{@pass_date}
          Last Logon: #{@logon_time} #{@logon_date}
          Logon Count: #{@logon_count}
          #{uac_string}
          Hash History:
          #{hash_history}
          EOS
        end

        # @return [String] the NTLM hash string for the current password
        def ntlm_hash
          "#{@lm_hash}:#{@nt_hash}"
        end

        # @return [String] Each historical NTLM Hash on a new line
        def hash_history
          history_string = ''
          @lm_history.each_with_index do | lm_hash, index|
            history_string << "#{@name}:#{@rid}:#{lm_hash}:#{@nt_history[index]}\n"
          end
          history_string
        end

        private

        def get_boolean(data)
          get_int(data) == 1
        end

        def get_hash_history(data)
          raw_history = data.slice!(0,HASH_HISTORY_SIZE)
          split_history = raw_history.scan(/.{1,33}/)
          split_history.map!{ |hash| hash.gsub(/\x00/,'')}
          split_history.reject!{ |hash| hash.blank? }
        end

        def get_int(data)
          data.slice!(0,4).unpack('L').first
        end

        def get_string(data,length)
          data.slice!(0,length).force_encoding("UTF-8").gsub(/\x00/,'')
        end

        def uac_string
          status_string = ''
          if @disabled
            status_string << " - Account Disabled\n"
          end
          if @expired
            status_string << " - Password Expired\n"
          end
          if @locked
            status_string << " - Account Locked Out\n"
          end
          if @no_expire
            status_string << " - Password Never Expires\n"
          end
          if @no_pass
            status_string << " - No Password Required\n"
          end
          status_string
        end
      end
    end
  end
end
