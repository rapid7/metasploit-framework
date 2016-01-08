require 'openssl'

module Net::SSH::Transport

  # Pure-Ruby implementation of Stateful Decryption Counter(SDCTR) Mode
  # for Block Ciphers. See RFC4344 for detail.
  module CTR
    def self.extended(orig)
      orig.instance_eval {
        @remaining = ""
        @counter = nil
        @counter_len = orig.block_size
        orig.encrypt
        orig.padding = 0
      }

      class <<orig
        alias :_update :update
        private :_update
        undef :update

        def iv
          @counter
        end

        def iv_len
          block_size
        end

        def iv=(iv_s)
          @counter = iv_s if @counter.nil?
        end

        def encrypt
          # DO NOTHING (always set to "encrypt")
        end

        def decrypt
          # DO NOTHING (always set to "encrypt")
        end

        def padding=(pad)
          # DO NOTHING (always 0)
        end

        def reset
          @remaining = ""
        end

        def update(data)
          @remaining += data

          encrypted = ""

          while @remaining.bytesize >= block_size
            encrypted += xor!(@remaining.slice!(0, block_size),
                              _update(@counter))
            increment_counter!
          end

          encrypted
        end

        def final
          unless @remaining.empty?
            s = xor!(@remaining, _update(@counter))
          else
            s = ""
          end

          @remaining = ""

          s
        end

        private

        def xor!(s1, s2)
          s = []
          s1.unpack('Q*').zip(s2.unpack('Q*')) {|a,b| s.push(a^b) }
          s.pack('Q*')
        end

        def increment_counter!
          c = @counter_len
          while ((c -= 1) > 0)
            if @counter.setbyte(c, (@counter.getbyte(c) + 1) & 0xff) != 0
              break
            end
          end
        end
      end
    end
  end
end
