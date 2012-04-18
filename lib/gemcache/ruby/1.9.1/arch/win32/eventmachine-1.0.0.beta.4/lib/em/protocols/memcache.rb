module EventMachine
  module Protocols
    # Implements the Memcache protocol (http://code.sixapart.com/svn/memcached/trunk/server/doc/protocol.txt).
    # Requires memcached >= 1.2.4 w/ noreply support
    #
    # == Usage example
    #
    #   EM.run{
    #     cache = EM::P::Memcache.connect 'localhost', 11211
    #
    #     cache.set :a, 'hello'
    #     cache.set :b, 'hi'
    #     cache.set :c, 'how are you?'
    #     cache.set :d, ''
    #
    #     cache.get(:a){ |v| p v }
    #     cache.get_hash(:a, :b, :c, :d){ |v| p v }
    #     cache.get(:a,:b,:c,:d){ |a,b,c,d| p [a,b,c,d] }
    #
    #     cache.get(:a,:z,:b,:y,:d){ |a,z,b,y,d| p [a,z,b,y,d] }
    #
    #     cache.get(:missing){ |m| p [:missing=, m] }
    #     cache.set(:missing, 'abc'){ p :stored }
    #     cache.get(:missing){ |m| p [:missing=, m] }
    #     cache.del(:missing){ p :deleted }
    #     cache.get(:missing){ |m| p [:missing=, m] }
    #   }
    #
    module Memcache
      include EM::Deferrable

      ##
      # constants

      unless defined? Cempty
        # @private
        Cstored    = 'STORED'.freeze
        # @private
        Cend       = 'END'.freeze
        # @private
        Cdeleted   = 'DELETED'.freeze
        # @private
        Cunknown   = 'NOT_FOUND'.freeze
        # @private
        Cerror     = 'ERROR'.freeze

        # @private
        Cempty     = ''.freeze
        # @private
        Cdelimiter = "\r\n".freeze
      end

      ##
      # commands

      # Get the value associated with one or multiple keys
      #
      #  cache.get(:a){ |v| p v }
      #  cache.get(:a,:b,:c,:d){ |a,b,c,d| p [a,b,c,d] }
      #
      def get *keys
        raise ArgumentError unless block_given?

        callback{
          keys = keys.map{|k| k.to_s.gsub(/\s/,'_') }
          send_data "get #{keys.join(' ')}\r\n"
          @get_cbs << [keys, proc{ |values|
            yield *keys.map{ |k| values[k] }
          }]
        }
      end

      # Set the value for a given key
      #
      #  cache.set :a, 'hello'
      #  cache.set(:missing, 'abc'){ puts "stored the value!" }
      #
      def set key, val, exptime = 0, &cb
        callback{
          val = val.to_s
          send_cmd :set, key, 0, exptime, val.respond_to?(:bytesize) ? val.bytesize : val.size, !block_given?
          send_data val
          send_data Cdelimiter
          @set_cbs << cb if cb
        }
      end

      # Gets multiple values as a hash
      #
      #  cache.get_hash(:a, :b, :c, :d){ |h| puts h[:a] }
      #
      def get_hash *keys
        raise ArgumentError unless block_given?

        get *keys do |*values|
          yield keys.inject({}){ |hash, k| hash.update k => values[keys.index(k)] }
        end
      end

      # Delete the value associated with a key
      #
      #  cache.del :a
      #  cache.del(:b){ puts "deleted the value!" }
      #
      def delete key, expires = 0, &cb
        callback{
          send_data "delete #{key} #{expires}#{cb ? '' : ' noreply'}\r\n"
          @del_cbs << cb if cb
        }
      end
      alias del delete

      # Connect to a memcached server (must support NOREPLY, memcached >= 1.2.4)
      def self.connect host = 'localhost', port = 11211
        EM.connect host, port, self, host, port
      end

      def send_cmd cmd, key, flags = 0, exptime = 0, bytes = 0, noreply = false
        send_data "#{cmd} #{key} #{flags} #{exptime} #{bytes}#{noreply ? ' noreply' : ''}\r\n"
      end
      private :send_cmd

      ##
      # errors

      # @private
      class ParserError < StandardError
      end

      ##
      # em hooks

      # @private
      def initialize host, port = 11211
        @host, @port = host, port
      end

      # @private
      def connection_completed
        @get_cbs = []
        @set_cbs = []
        @del_cbs = []

        @values = {}

        @reconnecting = false
        @connected = true
        succeed
        # set_delimiter "\r\n"
        # set_line_mode
      end

      #--
      # 19Feb09 Switched to a custom parser, LineText2 is recursive and can cause
      #         stack overflows when there is too much data.
      # include EM::P::LineText2
      # @private
      def receive_data data
        (@buffer||='') << data

        while index = @buffer.index(Cdelimiter)
          begin
            line = @buffer.slice!(0,index+2)
            process_cmd line
          rescue ParserError
            @buffer[0...0] = line
            break
          end
        end
      end

      #--
      # def receive_line line
      # @private
      def process_cmd line
        case line.strip
        when /^VALUE\s+(.+?)\s+(\d+)\s+(\d+)/ # VALUE <key> <flags> <bytes>
          bytes = Integer($3)
          # set_binary_mode bytes+2
          # @cur_key = $1
          if @buffer.size >= bytes + 2
            @values[$1] = @buffer.slice!(0,bytes)
            @buffer.slice!(0,2) # \r\n
          else
            raise ParserError
          end

        when Cend # END
          if entry = @get_cbs.shift
            keys, cb = entry
            cb.call(@values)
          end
          @values = {}

        when Cstored # STORED
          if cb = @set_cbs.shift
            cb.call(true)
          end

        when Cdeleted # DELETED
          if cb = @del_cbs.shift
            cb.call(true)
          end

        when Cunknown # NOT_FOUND
          if cb = @del_cbs.shift
            cb.call(false)
          end

        else
          p [:MEMCACHE_UNKNOWN, line]
        end
      end

      #--
      # def receive_binary_data data
      #   @values[@cur_key] = data[0..-3]
      # end

      # @private
      def unbind
        if @connected or @reconnecting
          EM.add_timer(1){ reconnect @host, @port }
          @connected = false
          @reconnecting = true
          @deferred_status = nil
        else
          raise 'Unable to connect to memcached server'
        end
      end
    end
  end
end

if __FILE__ == $0
  # ruby -I ext:lib -r eventmachine -rubygems lib/protocols/memcache.rb
  require 'em/spec'

  # @private
  class TestConnection
    include EM::P::Memcache
    def send_data data
      sent_data << data
    end
    def sent_data
      @sent_data ||= ''
    end

    def initialize
      connection_completed
    end
  end

  EM.describe EM::Protocols::Memcache do

    before{
      @c = TestConnection.new
    }

    should 'send get requests' do
      @c.get('a'){}
      @c.sent_data.should == "get a\r\n"
      done
    end

    should 'send set requests' do
      @c.set('a', 1){}
      @c.sent_data.should == "set a 0 0 1\r\n1\r\n"
      done
    end

    should 'use noreply on set without block' do
      @c.set('a', 1)
      @c.sent_data.should == "set a 0 0 1 noreply\r\n1\r\n"
      done
    end

    should 'send delete requests' do
      @c.del('a')
      @c.sent_data.should == "delete a 0 noreply\r\n"
      done
    end

    should 'work when get returns no values' do
      @c.get('a'){ |a|
        a.should.be.nil
        done
      }

      @c.receive_data "END\r\n"
    end

    should 'invoke block on set' do
      @c.set('a', 1){
        done
      }

      @c.receive_data "STORED\r\n"
    end

    should 'invoke block on delete' do
      @c.delete('a'){ |found|
        found.should.be.false
      }
      @c.delete('b'){ |found|
        found.should.be.true
        done
      }

      @c.receive_data "NOT_FOUND\r\n"
      @c.receive_data "DELETED\r\n"
    end

    should 'parse split responses' do
      @c.get('a'){ |a|
        a.should == 'abc'
        done
      }

      @c.receive_data "VAL"
      @c.receive_data "UE a 0 "
      @c.receive_data "3\r\n"
      @c.receive_data "ab"
      @c.receive_data "c"
      @c.receive_data "\r\n"
      @c.receive_data "EN"
      @c.receive_data "D\r\n"
    end

  end
end
