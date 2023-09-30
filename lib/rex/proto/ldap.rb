require 'net/ldap'
require 'rex/socket'

#
# This file monkeypatches the upstream net/ldap library to add support for the proxies datastore option,
# supporting blocking synchronrous reads, and using a Rex Socket to work with Rex's Switchboard functionality
# TODO: write a real LDAP client in Rex and migrate all consumers
#

# Update Net::LDAP's initialize and new_connection method to honor a tracking proxies setting
class Net::LDAP
  # Reference the old initialize method, and ensure `reload_lib -a` doesn't attempt to refine the method
  alias_method :_old_initialize, :initialize unless defined?(_old_initialize)

  # Orignal Source:
  # https://github.com/ruby-ldap/ruby-net-ldap/blob/95cec3822cd2f60787971e19714f74fd5999595c/lib/net/ldap.rb#L548
  # Additionally tracks proxies configuration, used when making a new_connection
  def initialize(args = {})
    _old_initialize(args)
    @proxies = args[:proxies]
  end

  private

  # Original source:
  # https://github.com/ruby-ldap/ruby-net-ldap/blob/95cec3822cd2f60787971e19714f74fd5999595c/lib/net/ldap.rb#L1321
  # Updated to include proxies configuration
  def new_connection
    connection = Net::LDAP::Connection.new \
    :host                    => @host,
    :port                    => @port,
    :hosts                   => @hosts,
    :encryption              => @encryption,
    :instrumentation_service => @instrumentation_service,
    :connect_timeout         => @connect_timeout,
    # New:
    :proxies                 => @proxies

    # Force connect to see if there's a connection error
    connection.socket
    connection
  rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
    @result = {
      :resultCode   => 52,
      :errorMessage => ResultStrings[ResultCodeUnavailable],
    }
    raise e
  end
end

# Update Net::LDAP's initialize and new_connection method to honor a tracking proxies setting
class Net::LDAP::Connection # :nodoc:
  module SynchronousRead
    # Read `length` bytes of data from the LDAP connection socket and
    # return this data as a string.
    #
    # @param length [Integer] Length of the data to be read from the LDAP connection socket.
    # @param _opts [Hash] Unused
    #
    # @return [String] A string containing the data read from the LDAP connection socket.
    def read(length = nil, _opts = {})
      data = ''
      loop do
        chunk = super(length - data.length)
        if chunk.nil?
          return data == '' ? nil : data
        end

        data << chunk
        break if data.length == length
      end

      data
    end
  end

  # Initialize the LDAP connection using Rex::Socket::TCP,
  # and optionally set up encryption on the connection if configured.
  #
  # @param server [Hash] Hash of the options needed to set
  #   up the Rex::Socket::TCP socket for the LDAP connection.
  # @see http://gemdocs.org/gems/rex-socket/0.1.43/Rex/Socket.html#create-class_method
  # @see http://gemdocs.org/gems/rex-socket/0.1.43/Rex/Socket.html#create_param-class_method
  # @see http://gemdocs.org/gems/rex-socket/0.1.43/Rex/Socket/Parameters.html#from_hash-class_method
  def initialize(server)
    begin
      @conn = Rex::Socket::Tcp.create(
        'PeerHost' => server[:host],
        'PeerPort' => server[:port],
        'Proxies' => server[:proxies]
      )
      @conn.extend(SynchronousRead)
    rescue SocketError
      raise Net::LDAP::LdapError, 'No such address or other socket error.'
    rescue Errno::ECONNREFUSED
      raise Net::LDAP::LdapError, "Server #{server[:host]} refused connection on port #{server[:port]}."
    end

    if server[:encryption]
      setup_encryption server[:encryption]
    end

    yield self if block_given?
  end

  # Monkeypatch upstream library for now to support :controls
  # hash option in `args` so that we can provide controls within
  # searches. Needed so we can specify the LDAP_SERVER_SD_FLAGS_OID
  # flag for searches to prevent getting the SACL when querying for
  # ntSecurityDescriptor, as this is retrieved by default and non-admin
  # users are not allowed to retrieve SACLs for objects. Therefore by
  # adjusting the search to not retrieve SACLs, non-admin users can still
  # retrieve information about the security of objects without violating this rule.
  #
  # @see https://github.com/rapid7/metasploit-framework/issues/17324
  # @see https://github.com/ruby-ldap/ruby-net-ldap/pull/411
  #
  # @param [Hash] args A hash of the arguments to be utilized by the search operation.
  # @return [Net::LDAP::PDU] A Protocol Data Unit (PDU) object, represented by
  #   the Net::LDAP::PDU class, containing the results of the search operation.
  def search(args = nil)
    args ||= {}

    # filtering, scoping, search base
    # filter: https://tools.ietf.org/html/rfc4511#section-4.5.1.7
    # base:   https://tools.ietf.org/html/rfc4511#section-4.5.1.1
    # scope:  https://tools.ietf.org/html/rfc4511#section-4.5.1.2
    filter = args[:filter] || Net::LDAP::Filter.eq("objectClass", "*")
    base   = args[:base]
    scope  = args[:scope] || Net::LDAP::SearchScope_WholeSubtree

    # attr handling
    # attrs:      https://tools.ietf.org/html/rfc4511#section-4.5.1.8
    # attrs_only: https://tools.ietf.org/html/rfc4511#section-4.5.1.6
    attrs  = Array(args[:attributes])
    attrs_only = args[:attributes_only] == true

    # references
    # refs:  https://tools.ietf.org/html/rfc4511#section-4.5.3
    # deref: https://tools.ietf.org/html/rfc4511#section-4.5.1.3
    refs   = args[:return_referrals] == true
    deref  = args[:deref] || Net::LDAP::DerefAliases_Never

    # limiting, paging, sorting
    # size: https://tools.ietf.org/html/rfc4511#section-4.5.1.4
    # time: https://tools.ietf.org/html/rfc4511#section-4.5.1.5
    size   = args[:size].to_i
    time   = args[:time].to_i
    paged  = args[:paged_searches_supported]
    sort   = args.fetch(:sort_controls, false)

    # arg validation
    raise ArgumentError, "search base is required" unless base
    raise ArgumentError, "invalid search-size" unless size >= 0
    raise ArgumentError, "invalid search scope" unless Net::LDAP::SearchScopes.include?(scope)
    raise ArgumentError, "invalid alias dereferencing value" unless Net::LDAP::DerefAliasesArray.include?(deref)

    # arg transforms
    filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)
    ber_attrs = attrs.map { |attr| attr.to_s.to_ber }
    ber_sort  = encode_sort_controls(sort)

    # An interesting value for the size limit would be close to A/D's
    # built-in page limit of 1000 records, but openLDAP newer than version
    # 2.2.0 chokes on anything bigger than 126. You get a silent error that
    # is easily visible by running slapd in debug mode. Go figure.
    #
    # Changed this around 06Sep06 to support a caller-specified search-size
    # limit. Because we ALWAYS do paged searches, we have to work around the
    # problem that it's not legal to specify a "normal" sizelimit (in the
    # body of the search request) that is larger than the page size we're
    # requesting. Unfortunately, I have the feeling that this will break
    # with LDAP servers that don't support paged searches!!!
    #
    # (Because we pass zero as the sizelimit on search rounds when the
    # remaining limit is larger than our max page size of 126. In these
    # cases, I think the caller's search limit will be ignored!)
    #
    # CONFIRMED: This code doesn't work on LDAPs that don't support paged
    # searches when the size limit is larger than 126. We're going to have
    # to do a root-DSE record search and not do a paged search if the LDAP
    # doesn't support it. Yuck.
    rfc2696_cookie = [126, ""]
    result_pdu = nil
    n_results = 0

    message_id = next_msgid

    instrument "search.net_ldap_connection",
               message_id: message_id,
               filter:     filter,
               base:       base,
               scope:      scope,
               size:       size,
               time:       time,
               sort:       sort,
               referrals:  refs,
               deref:      deref,
               attributes: attrs do |payload|
      loop do
        # should collect this into a private helper to clarify the structure
        query_limit = 0
        if size > 0
          query_limit = if paged
                          (((size - n_results) < 126) ? (size - n_results) : 0)
                        else
                          size
                        end
        end

        request = [
          base.to_ber,
          scope.to_ber_enumerated,
          deref.to_ber_enumerated,
          query_limit.to_ber, # size limit
          time.to_ber,
          attrs_only.to_ber,
          filter.to_ber,
          ber_attrs.to_ber_sequence,
        ].to_ber_appsequence(Net::LDAP::PDU::SearchRequest)

        # rfc2696_cookie sometimes contains binary data from Microsoft Active Directory
        # this breaks when calling to_ber. (Can't force binary data to UTF-8)
        # we have to disable paging (even though server supports it) to get around this...

        user_controls = args.fetch(:controls, [])
        controls = []
        controls <<
          [
            Net::LDAP::LDAPControls::PAGED_RESULTS.to_ber,
            # Criticality MUST be false to interoperate with normal LDAPs.
            false.to_ber,
            rfc2696_cookie.map(&:to_ber).to_ber_sequence.to_s.to_ber,
          ].to_ber_sequence if paged
        controls << ber_sort if ber_sort
        if controls.empty? && user_controls.empty?
          controls = nil
        else
          controls += user_controls
          controls = controls.to_ber_contextspecific(0)
        end

        write(request, controls, message_id)

        result_pdu = nil
        controls = []

        while pdu = queued_read(message_id)
          case pdu.app_tag
          when Net::LDAP::PDU::SearchReturnedData
            n_results += 1
            yield pdu.search_entry if block_given?
          when Net::LDAP::PDU::SearchResultReferral
            if refs
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
          when Net::LDAP::PDU::SearchResult
            result_pdu = pdu
            controls = pdu.result_controls
            if refs && pdu.result_code == Net::LDAP::ResultCodeReferral
              if block_given?
                se = Net::LDAP::Entry.new
                se[:search_referrals] = (pdu.search_referrals || [])
                yield se
              end
            end
            break
          else
            raise Net::LDAP::ResponseTypeInvalidError, "invalid response-type in search: #{pdu.app_tag}"
          end
        end

        if result_pdu.nil?
          raise Net::LDAP::ResponseMissingOrInvalidError, "response missing"
        end

        # count number of pages of results
        payload[:page_count] ||= 0
        payload[:page_count]  += 1

        # When we get here, we have seen a type-5 response. If there is no
        # error AND there is an RFC-2696 cookie, then query again for the next
        # page of results. If not, we're done. Don't screw this up or we'll
        # break every search we do.
        #
        # Noticed 02Sep06, look at the read_ber call in this loop, shouldn't
        # that have a parameter of AsnSyntax? Does this just accidentally
        # work? According to RFC-2696, the value expected in this position is
        # of type OCTET STRING, covered in the default syntax supported by
        # read_ber, so I guess we're ok.
        more_pages = false
        if result_pdu.result_code == Net::LDAP::ResultCodeSuccess and controls
          controls.each do |c|
            if c.oid == Net::LDAP::LDAPControls::PAGED_RESULTS
              # just in case some bogus server sends us more than 1 of these.
              more_pages = false
              if c.value and c.value.length > 0
                cookie = c.value.read_ber[1]
                if cookie and cookie.length > 0
                  rfc2696_cookie[1] = cookie
                  more_pages = true
                end
              end
            end
          end
        end

        break unless more_pages
      end # loop

      # track total result count
      payload[:result_count] = n_results

      result_pdu || OpenStruct.new(:status => :failure, :result_code => Net::LDAP::ResultCodeOperationsError, :message => "Invalid search")
    end # instrument
  ensure

    # clean up message queue for this search
    messages = message_queue.delete(message_id)

    # in the exceptional case some messages were *not* consumed from the queue,
    # instrument the event but do not fail.
    if !messages.nil? && !messages.empty?
      instrument "search_messages_unread.net_ldap_connection",
                 message_id: message_id, messages: messages
    end
  end

  # Another monkeypatch to support :controls
  def modify(args)
    modify_dn = args[:dn] or raise "Unable to modify empty DN"
    ops = self.class.modify_ops args[:operations]

    message_id = next_msgid
    request    = [
      modify_dn.to_ber,
      ops.to_ber_sequence,
    ].to_ber_appsequence(Net::LDAP::PDU::ModifyRequest)

    controls = args.fetch(:controls, nil)
    unless controls.nil?
      controls = controls.to_ber_contextspecific(0)
    end

    write(request, controls, message_id)
    pdu = queued_read(message_id)

    if !pdu || pdu.app_tag != Net::LDAP::PDU::ModifyResponse
      raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
    end

    pdu
  end
end

module Rex
  module Proto
    module LDAP
    end
  end
end
