module Net 
  module SSH 
    module Transport
      module KeyExpander
    
        # Generate a key value in accordance with the SSH2 specification.
        # (RFC4253 7.2. "Output from Key Exchange")
        def self.expand_key(bytes, start, options={})
          if bytes == 0
            return ""
          end
      
          k = start[0, bytes]
          return k if k.length >= bytes
      
          digester = options[:digester] or raise 'No digester supplied'
          shared   = options[:shared] or raise 'No shared secret supplied'
          hash     = options[:hash] or raise 'No hash supplied'
      
          while k.length < bytes
            step = digester.digest(shared + hash + k)
            bytes_needed = bytes - k.length
            k << step[0, bytes_needed]
          end
      
          return k
        end
      end
    end
  end
end
