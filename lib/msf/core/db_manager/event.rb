module Msf::DBManager::Event
  DEFAULT_ORDER = :desc
  DEFAULT_LIMIT = 100
  DEFAULT_OFFSET = 0

  # Retrieves events that are stored in the database.
  #
  # @param opts [Hash] Hash containing query key-value pairs based on the event model.
  # @option opts :id [Integer] A specific event ID. If specified, all other options are ignored.
  #
  # Additional query options:
  # @option opts :workspace [String] The workspace from which the data should be gathered from. (Required)
  # @option opts :order [Symbol|String] The event created_at sort order.
  #   Valid values: :asc, :desc, 'asc' or 'desc'. Default: :desc
  # @option opts :limit [Integer] The maximum number of events that will be retrieved from the query.
  #   Default: 100
  # @option opts :offset [Integer] The number of events the query will begin reading from the start
  #   of the set. Default: 0
  # @option opts :search_term [String] Search regular expression used to filter results.
  #   All fields are converted to strings and results are returned if the pattern is matched.
  # @return [Array<Mdm::Event>|Mdm::Event::ActiveRecord_AssociationRelation] events that are matched.
  def events(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    # If we have the ID, there is no point in creating a complex query.
    if opts[:id] && !opts[:id].to_s.empty?
      return Array.wrap(Mdm::Event.find(opts[:id]))
    end

    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    order = opts.delete(:order)
    order = order.nil? ? DEFAULT_ORDER : order.to_sym

    limit = opts.delete(:limit) || DEFAULT_LIMIT
    offset = opts.delete(:offset) || DEFAULT_OFFSET

    search_term = opts.delete(:search_term)
    results = wspace.events.where(opts).order(created_at: order).offset(offset).limit(limit)

    if search_term && !search_term.empty?
      re_search_term = /#{search_term}/mi
      results = results.select { |event|
        event.attribute_names.any? { |a| event[a.intern].to_s.match(re_search_term) }
      }
    end
    results
  }
  end

  def report_event(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    return if not wspace # Temp fix?
    uname  = opts.delete(:username)

    if !opts[:host].nil? && !opts[:host].kind_of?(::Mdm::Host)
      opts[:host] = find_or_create_host(workspace: wspace, host: opts[:host])
    end

    ::Mdm::Event.create(opts.merge(:workspace_id => wspace[:id], :username => uname))
  }
  end
end