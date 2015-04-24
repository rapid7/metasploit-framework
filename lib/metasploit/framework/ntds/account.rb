module Metasploit
  module Framework
    module NTDS
      # This class represents an NTDS account structure as sent back by Meterpreter's
      # priv extension.
      class Account

        attr_accessor :name
        attr_accessor :description
        attr_accessor :rid
        attr_accessor :disabled
        attr_accessor :locked
        attr_accessor :no_pass
        attr_accessor :no_expire
        attr_accessor :expired
        attr_accessor :logon_count
        attr_accessor :nt_history_count
        attr_accessor :lm_history_count
        attr_accessor :expiry_date
        attr_accessor :logon_date
        attr_accessor :logon_time
        attr_accessor :pass_date
        attr_accessor :pass_time
        attr_accessor :lm_hash
        attr_accessor :nt_hash
        attr_accessor :lm_history
        attr_accessor :nt_history
        attr_accessor :sid


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
