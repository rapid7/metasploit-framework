require 'digest'
require 'rex/text'

module Rex
  module Proto
    module Http
      class AuthDigest

        def make_cnonce
          Digest::MD5.hexdigest '%x' % (::Time.now.to_i + rand(65535))
        end

        def digest(digest_user, digest_password, method, path, parameters, iis = false)
          cnonce = make_cnonce
          nonce_count = 1

          qop = parameters['qop']

          if parameters['algorithm'] =~ /(.*?)(-sess)?$/
            algorithm = case ::Regexp.last_match(1)
                        when 'MD5' then Digest::MD5
                        when 'MD-5' then Digest::MD5
                        when 'SHA1' then Digest::SHA1
                        when 'SHA-1' then Digest::SHA1
                        when 'SHA2' then Digest::SHA2
                        when 'SHA-2' then Digest::SHA2
                        when 'SHA256' then Digest::SHA256
                        when 'SHA-256' then Digest::SHA256
                        when 'SHA384' then Digest::SHA384
                        when 'SHA-384' then Digest::SHA384
                        when 'SHA512' then Digest::SHA512
                        when 'SHA-512' then Digest::SHA512
                        when 'RMD160' then Digest::RMD160
                        else raise "unknown algorithm \"#{::Regexp.last_match(1)}\""
                        end
            algstr = parameters['algorithm']
            sess = ::Regexp.last_match(2)
          else
            algorithm = Digest::MD5
            algstr = 'MD5'
            sess = false
          end
          a1 = if sess
                 [
                   algorithm.hexdigest("#{digest_user}:#{parameters['realm']}:#{digest_password}"),
                   parameters['nonce'],
                   cnonce
                 ].join ':'
               else
                 "#{digest_user}:#{parameters['realm']}:#{digest_password}"
               end

          ha1 = algorithm.hexdigest(a1)
          ha2 = algorithm.hexdigest("#{method}:#{path}")

          request_digest = [ha1, parameters['nonce']]
          request_digest.push(('%08x' % nonce_count), cnonce, qop) if qop
          request_digest << ha2
          request_digest = request_digest.join ':'
          # Same order as IE7
          return [
            "Digest username=\"#{digest_user}\"",
            "realm=\"#{parameters['realm']}\"",
            "nonce=\"#{parameters['nonce']}\"",
            "uri=\"#{path}\"",
            "cnonce=\"#{cnonce}\"",
            "nc=#{'%08x' % nonce_count}",
            "algorithm=#{algstr}",
            "response=\"#{algorithm.hexdigest(request_digest)}\"",
            # The spec says the qop value shouldn't be enclosed in quotes, but
            # some versions of IIS require it and Apache accepts it.  Chrome
            # and Firefox both send it without quotes but IE does it this way.
            # Use the non-compliant-but-everybody-does-it to be as compatible
            # as possible by default.  The user can override if they don't like
            # it.
            if iis
              "qop=\"#{qop}\""
            else
              "qop=#{qop}"
            end,
            if parameters.key? 'opaque'
              "opaque=\"#{parameters['opaque']}\""
            end
          ].compact
        end
      end
    end
  end
end
