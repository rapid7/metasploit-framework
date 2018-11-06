require 'openssl'
require 'delegate'

module Net::SSH::Transport
  #:nodoc:
  class OpenSSLAESCTR < SimpleDelegator
    def initialize(original)
      super
      @was_reset = false
    end

    def block_size
      16
    end

    def self.block_size
      16
    end

    def reset
      @was_reset = true
    end

    def iv=(iv_s)
      super unless @was_reset
    end
  end

  #:nodoc:
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

        singleton_class.send(:alias_method, :_update, :update)
        singleton_class.send(:private, :_update)
        singleton_class.send(:undef_method, :update)

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

          offset = 0
          while (@remaining.bytesize - offset) >= block_size
            encrypted += xor!(@remaining.slice(offset, block_size),
                              _update(@counter))
            increment_counter!
            offset += block_size
          end
          @remaining = @remaining.slice(offset..-1)

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

        def xor!(s1, s2)
          s = []
          s1.unpack('Q*').zip(s2.unpack('Q*')) {|a,b| s.push(a ^ b) }
          s.pack('Q*')
        end
        singleton_class.send(:private, :xor!)

        def increment_counter!
          c = @counter_len
          while ((c -= 1) > 0)
            if @counter.setbyte(c, (@counter.getbyte(c) + 1) & 0xff) != 0
              break
            end
          end
        end
        singleton_class.send(:private, :increment_counter!)
      }
    end
  end
end
