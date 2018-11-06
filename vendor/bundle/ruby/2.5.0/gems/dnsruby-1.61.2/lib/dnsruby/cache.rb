# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++


# # This class implements a cache.
# It stores data under qname-qclass-qtype tuples.
# Each tuple indexes a CacheData object (which
# stores a Message, and an expiration).
# If a new Message is stored to a tuple, it will
# overwrite the previous Message.
# When a Message is retrieved from the cache, the header
# and ttls will be "fixed" - i.e. AA cleared, etc.



# @TODO@ Max size for cache?
module Dnsruby
  class Cache # :nodoc: all
    def initialize()
    @cache = Hash.new
    @@max_size = 16*1024 # Get this right...
    @mutex = Mutex.new
    end
    def cache
      @cache
    end
    def clear()
      @mutex.synchronize {
        @cache = Hash.new
      }
    end
    def length
      return @cache.length
    end
    def Cache.max_size=(length)
       @@max_size = length
    end
    def add(message)
      q = message.question[0]
      key = CacheKey.new(q.qname, q.qtype, q.qclass).to_s
      data = CacheData.new(message)
      @mutex.synchronize {
        if (@cache[key])
          TheLog.debug("CACHE REPLACE : #{q.qname}, #{q.qtype}\n")
        else
          TheLog.debug("CACHE ADD : #{q.qname}, #{q.qtype}\n")
        end
        @cache[key] = data

        while @cache.size > @@max_size # keep the cache size reasonable
          @cache.shift
        end
      }
    end
    #  This method "fixes up" the response, so that the header and ttls are OK
    #  The resolver will still need to copy the flags and ID across from the query
    def find(qname, qtype, qclass = Classes.IN)
#      print "CACHE find : #{qname}, #{qtype}\n"
      qn = Name.create(qname)
      qn.absolute = true
      key = CacheKey.new(qn, qtype, qclass).to_s
      @mutex.synchronize {
        data = @cache[key]
        if (!data)
#          print "CACHE lookup failed\n"
          return nil
        end
        if (data.expiration <= Time.now.to_i)
          @cache.delete(key)
          TheLog.debug("CACHE lookup stale\n")
          return nil
        end
        m = data.message
        TheLog.debug("CACHE found\n")
        return m
      }
    end
    def Cache.delete(qname, qtype, qclass = Classes.IN)
      key = CacheKey.new(qname, qtype, qclass)
      @mutex.synchronize {
        @cache.delete(key)
      }
    end
    class CacheKey # :nodoc: all
      attr_accessor :qname, :qtype, :qclass
      def initialize(*args)
        self.qclass = Classes.IN
        if (args.length > 0)
          self.qname = Name.create(args[0])
          self.qname.absolute = true
          if (args.length > 1)
            self.qtype = Types.new(args[1])
            if (args.length > 2)
              self.qclass = Classes.new(args[2])
            end
          end
        end
      end
      def to_s
        return "#{qname.inspect.downcase} #{qclass} #{qtype}"
      end
    end
    class CacheData # :nodoc: all
      attr_reader :expiration
      def message=(m)
        @expiration = get_expiration(m)
        @message = Message.decode(m.encode(true))
        @message.cached = true
      end
      def message
        m = Message.decode(@message.encode)
        m.cached = true
        #  @TODO@ What do we do about answerfrom, answersize, etc.?
        m.header.aa = false # Anything else to do here?
        #  Fix up TTLs!!
        offset = (Time.now - @time_stored).to_i
        m.each_resource {|rr|
          next if rr.type == Types::OPT
          rr.ttl = rr.ttl - offset
        }
        return m
      end
      def get_expiration(m)
        #  Find the minimum ttl of any of the rrsets
        min_ttl = 9999999
        m.each_section {|section|
          section.rrsets.each {|rrset|
            if (rrset.ttl < min_ttl)
              min_ttl = rrset.ttl
            end
          }
        }
        if (min_ttl == 9999999)
          return 0
        end
        return (Time.now.to_i + min_ttl)
      end
      def initialize(*args)
        @expiration = 0
        @time_stored = Time.now.to_i
        self.message=(args[0])
      end
      def to_s
        return "#{self.message}"
      end
    end
  end
end