module Rack
  module Cache

    # Parses a Cache-Control header and exposes the directives as a Hash.
    # Directives that do not have values are set to +true+.
    class CacheControl < Hash
      def initialize(value=nil)
        parse(value)
      end

      # Indicates that the response MAY be cached by any cache, even if it
      # would normally be non-cacheable or cacheable only within a non-
      # shared cache.
      #
      # A response may be considered public without this directive if the
      # private directive is not set and the request does not include an
      # Authorization header.
      def public?
        self['public']
      end

      # Indicates that all or part of the response message is intended for
      # a single user and MUST NOT be cached by a shared cache. This
      # allows an origin server to state that the specified parts of the
      # response are intended for only one user and are not a valid
      # response for requests by other users. A private (non-shared) cache
      # MAY cache the response.
      #
      # Note: This usage of the word private only controls where the
      # response may be cached, and cannot ensure the privacy of the
      # message content.
      def private?
        self['private']
      end

      # When set in a response, a cache MUST NOT use the response to satisfy a
      # subsequent request without successful revalidation with the origin
      # server. This allows an origin server to prevent caching even by caches
      # that have been configured to return stale responses to client requests.
      #
      # Note that this does not necessary imply that the response may not be
      # stored by the cache, only that the cache cannot serve it without first
      # making a conditional GET request with the origin server.
      #
      # When set in a request, the server MUST NOT use a cached copy for its
      # response. This has quite different semantics compared to the no-cache
      # directive on responses. When the client specifies no-cache, it causes
      # an end-to-end reload, forcing each cache to update their cached copies.
      def no_cache?
        self['no-cache']
      end

      # Indicates that the response MUST NOT be stored under any circumstances.
      #
      # The purpose of the no-store directive is to prevent the
      # inadvertent release or retention of sensitive information (for
      # example, on backup tapes). The no-store directive applies to the
      # entire message, and MAY be sent either in a response or in a
      # request. If sent in a request, a cache MUST NOT store any part of
      # either this request or any response to it. If sent in a response,
      # a cache MUST NOT store any part of either this response or the
      # request that elicited it. This directive applies to both non-
      # shared and shared caches. "MUST NOT store" in this context means
      # that the cache MUST NOT intentionally store the information in
      # non-volatile storage, and MUST make a best-effort attempt to
      # remove the information from volatile storage as promptly as
      # possible after forwarding it.
      #
      # The purpose of this directive is to meet the stated requirements
      # of certain users and service authors who are concerned about
      # accidental releases of information via unanticipated accesses to
      # cache data structures. While the use of this directive might
      # improve privacy in some cases, we caution that it is NOT in any
      # way a reliable or sufficient mechanism for ensuring privacy. In
      # particular, malicious or compromised caches might not recognize or
      # obey this directive, and communications networks might be
      # vulnerable to eavesdropping.
      def no_store?
        self['no-store']
      end

      # The expiration time of an entity MAY be specified by the origin
      # server using the Expires header (see section 14.21). Alternatively,
      # it MAY be specified using the max-age directive in a response. When
      # the max-age cache-control directive is present in a cached response,
      # the response is stale if its current age is greater than the age
      # value given (in seconds) at the time of a new request for that
      # resource. The max-age directive on a response implies that the
      # response is cacheable (i.e., "public") unless some other, more
      # restrictive cache directive is also present.
      #
      # If a response includes both an Expires header and a max-age
      # directive, the max-age directive overrides the Expires header, even
      # if the Expires header is more restrictive. This rule allows an origin
      # server to provide, for a given response, a longer expiration time to
      # an HTTP/1.1 (or later) cache than to an HTTP/1.0 cache. This might be
      # useful if certain HTTP/1.0 caches improperly calculate ages or
      # expiration times, perhaps due to desynchronized clocks.
      #
      # Many HTTP/1.0 cache implementations will treat an Expires value that
      # is less than or equal to the response Date value as being equivalent
      # to the Cache-Control response directive "no-cache". If an HTTP/1.1
      # cache receives such a response, and the response does not include a
      # Cache-Control header field, it SHOULD consider the response to be
      # non-cacheable in order to retain compatibility with HTTP/1.0 servers.
      #
      # When the max-age directive is included in the request, it indicates
      # that the client is willing to accept a response whose age is no
      # greater than the specified time in seconds.
      def max_age
        self['max-age'].to_i  if key?('max-age')
      end

      # If a response includes an s-maxage directive, then for a shared
      # cache (but not for a private cache), the maximum age specified by
      # this directive overrides the maximum age specified by either the
      # max-age directive or the Expires header. The s-maxage directive
      # also implies the semantics of the proxy-revalidate directive. i.e.,
      # that the shared cache must not use the entry after it becomes stale
      # to respond to a subsequent request without first revalidating it with
      # the origin server. The s-maxage directive is always ignored by a
      # private cache.
      def shared_max_age
        self['s-maxage'].to_i  if key?('s-maxage')
      end
      alias_method :s_maxage, :shared_max_age

      # Because a cache MAY be configured to ignore a server's specified
      # expiration time, and because a client request MAY include a max-
      # stale directive (which has a similar effect), the protocol also
      # includes a mechanism for the origin server to require revalidation
      # of a cache entry on any subsequent use. When the must-revalidate
      # directive is present in a response received by a cache, that cache
      # MUST NOT use the entry after it becomes stale to respond to a
      # subsequent request without first revalidating it with the origin
      # server. (I.e., the cache MUST do an end-to-end revalidation every
      # time, if, based solely on the origin server's Expires or max-age
      # value, the cached response is stale.)
      #
      # The must-revalidate directive is necessary to support reliable
      # operation for certain protocol features. In all circumstances an
      # HTTP/1.1 cache MUST obey the must-revalidate directive; in
      # particular, if the cache cannot reach the origin server for any
      # reason, it MUST generate a 504 (Gateway Timeout) response.
      #
      # Servers SHOULD send the must-revalidate directive if and only if
      # failure to revalidate a request on the entity could result in
      # incorrect operation, such as a silently unexecuted financial
      # transaction. Recipients MUST NOT take any automated action that
      # violates this directive, and MUST NOT automatically provide an
      # unvalidated copy of the entity if revalidation fails.
      def must_revalidate?
        self['must-revalidate']
      end

      # The proxy-revalidate directive has the same meaning as the must-
      # revalidate directive, except that it does not apply to non-shared
      # user agent caches. It can be used on a response to an
      # authenticated request to permit the user's cache to store and
      # later return the response without needing to revalidate it (since
      # it has already been authenticated once by that user), while still
      # requiring proxies that service many users to revalidate each time
      # (in order to make sure that each user has been authenticated).
      # Note that such authenticated responses also need the public cache
      # control directive in order to allow them to be cached at all.
      def proxy_revalidate?
        self['proxy-revalidate']
      end

      def to_s
        bools, vals = [], []
        each do |key,value|
          if value == true
            bools << key
          elsif value
            vals << "#{key}=#{value}"
          end
        end
        (bools.sort + vals.sort).join(', ')
      end

    private
      def parse(value)
        return  if value.nil? || value.empty?
        value.delete(' ').split(',').each do |part|
          next if part.empty?
          name, value = part.split('=', 2)
          self[name.downcase] = (value || true) unless name.empty?
        end
        self
      end
    end
  end
end
