module Metasploit
  module Framework
    module NTDS
      # This class represents an NTDS account structure as sent back by Meterpreter's
      # priv extension.
      class Account

        # @!attribute description
        #   @return [String] The AD Account Description
        attr_accessor :description
        # @!attribute disabled
        #   @return [TrueClass] If the AD account is disabled
        #   @return [FalseClass] If the AD account is not disabled
        attr_accessor :disabled
        # @!attribute expired
        #   @return [TrueClass] If the AD account password is expired
        #   @return [FalseClass] If the AD account password is not expired
        attr_accessor :expired
        # @!attribute expiry_date
        #   @return [String] Human Readable Date for the account's password expiration
        attr_accessor :expiry_date
        # @!attribute lm_hash
        #   @return [String] The LM Hash of the current password
        attr_accessor :lm_hash
        # @!attribute lm_history
        #   @return [Array<String>] The LM hashes for previous passwords, up to 24
        attr_accessor :lm_history
        # @!attribute lm_history_count
        #   @return [Fixnum] The count of historical LM hashes
        attr_accessor :lm_history_count
        # @!attribute locked
        #   @return [TrueClass] If the AD account is locked
        #   @return [FalseClass] If the AD account is not locked
        attr_accessor :locked
        # @!attribute logon_count
        #   @return [Fixnum] The number of times this account has logged in
        attr_accessor :logon_count
        # @!attribute logon_date
        #   @return [String] Human Readable Date for the last time the account logged in
        attr_accessor :logon_date
        # @!attribute logon_time
        #   @return [String] Human Readable Time for the last time the account logged in
        attr_accessor :logon_time
        # @!attribute name
        #   @return [String] The samAccountName of the account
        attr_accessor :name
        # @!attribute no_expire
        #   @return [TrueClass] If the AD account password does not expire
        #   @return [FalseClass] If the AD account password does expire
        attr_accessor :no_expire
        # @!attribute no_pass
        #   @return [TrueClass] If the AD account does not require a password
        #   @return [FalseClass] If the AD account does require a password
        attr_accessor :no_pass
        # @!attribute nt_hash
        #   @return [String] The NT Hash of the current password
        attr_accessor :nt_hash
        # @!attribute nt_history
        #   @return [Array<String>] The NT hashes for previous passwords, up to 24
        attr_accessor :nt_history
        # @!attribute nt_history_count
        #   @return [Fixnum] The count of historical NT hashes
        attr_accessor :nt_history_count
        # @!attribute pass_date
        #   @return [String] Human Readable Date for the last password change
        attr_accessor :pass_date
        # @!attribute pass_time
        #   @return [String] Human Readable Time for the last password change
        attr_accessor :pass_time
        # @!attribute rid
        #   @return [Fixnum] The Relative ID of the account
        attr_accessor :rid
        # @!attribute sid
        #   @return [String] Byte String for the Account's SID
        attr_accessor :sid

        # @param raw_data [String] the raw 3948 byte string from the wire
        # @raise [ArgumentErrror] if a 3948 byte string is not supplied
        def initialize(raw_data)
          raise ArgumentError, "No Data Supplied" unless raw_data.present?
          raise ArgumentError, "Invalid Data" unless raw_data.length == 3948
          data = raw_data.dup
          @name = get_string(data,40)
          @description = get_string(data,2048)
          @rid = get_int(data)
          @disabled = get_boolean(data)
          @locked = get_boolean(data)
          @no_pass = get_boolean(data)
          @no_expire = get_boolean(data)
          @expired = get_boolean(data)
          @logon_count = get_int(data)
          @nt_history_count = get_int(data)
          @lm_history_count = get_int(data)
          @expiry_data = get_string(data,30)
          @logon_data =  get_string(data,30)
          @logon_time = get_string(data,30)
          @pass_date = get_string(data,30)
          @pass_time = get_string(data,30)
          @lm_hash = get_string(data,33)
          @nt_hash = get_string(data,33)
          @lm_history = get_hash_history(data)
          @nt_history = get_hash_history(data)
          @sid = data
        end

        private

        def get_boolean(data)
          get_int(data) == 1
        end

        def get_hash_history(data)
          raw_history = data.slice!(0,792)
          split_history = raw_history.scan(/.{1,33}/)
          split_history.map!{ |hash| hash.gsub(/\x00/,'')}
          split_history.reject!{ |hash| hash.blank? }
        end

        def get_int(data)
          data.slice!(0,4).unpack('L').first
        end

        def get_string(data,length)
          data.slice!(0,length).gsub(/\x00/,'')
        end
      end
    end
  end
end
