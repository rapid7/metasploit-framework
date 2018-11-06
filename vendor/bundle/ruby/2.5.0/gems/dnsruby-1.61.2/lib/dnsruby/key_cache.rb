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

module Dnsruby
  class KeyCache #:nodoc: all
    #  Cache includes expiration time for keys
    #  Cache removes expired records
    def initialize(keys = nil)
      #  Store key tag against [expiry, key]
      @keys = {}
      add(keys)
    end
    def add_key_with_expiration(k, expiration)
      priv_add_key(k, expiration)
    end
    def add(k)
      if (k == nil)
        return false
      elsif (k.instance_of?RRSet)
        add_rrset(k)
      elsif (k.kind_of?KeyCache)
        kaes = k.keys_and_expirations
        kaes.keys.each { |keykey|
          #             priv_add_key(keykey, kaes[keykey])
          priv_add_key(keykey[1], keykey[0])
        }
      else
        raise ArgumentError.new("Expected an RRSet or KeyCache! Got #{k.class}")
      end
      return true
    end

    def add_rrset(k)
      #  Get expiration from the RRSIG
      #  There can be several RRSIGs here, one for each key which has signed the RRSet
      #  We want to choose the one with the most secure signing algorithm, key length,
      #  and the longest expiration time - not easy!
      #  for now, we simply accept all signed keys
      k.sigs.each { |sig|
        if (sig.type_covered = Types.DNSKEY)
          if (sig.inception <= Time.now.to_i)
            #  Check sig.expiration, sig.algorithm
            if (sig.expiration > Time.now.to_i)
              #  add the keys to the store
              k.rrs.each {|rr| priv_add_key(rr, sig.expiration)}
            end
          end
        end
      }
    end

    def priv_add_key(k, exp)
      #  Check that the key does not already exist with a longer expiration!
      if (@keys[k] == nil)
        @keys[k.key_tag] = [exp,k]
      elsif ((@keys[k])[0] < exp)
        @keys[k.key_tag] = [exp,k]
      end
    end

    def each
      #  Only offer currently-valid keys here
      remove_expired_keys
      @keys.values.each {|v| yield v[1]}
    end
    def keys
      #  Only offer currently-valid keys here
      remove_expired_keys
      ks = []
      @keys.values.each {|a| ks.push(a[1])}
      return ks
      #         return @keys.keys
    end
    def keys_and_expirations
      remove_expired_keys
      return keys.values
    end
    def remove_expired_keys
      @keys.delete_if {|k,v|
        v[0] < Time.now.to_i
      }
    end
    def find_key_for(name)
      each {|key| return key if key.name == name}
      return false
    end
  end
end