module Msf::DBManager::SessionEvent
  DEFAULT_ORDER = :desc
  DEFAULT_LIMIT = 100
  DEFAULT_OFFSET = 0

  # Retrieves session events that are stored in the database.
  #
  # @param opts [Hash] Hash containing query key-value pairs based on the session event model.
  # @option opts :id [Integer] A specific session event ID. If specified, all other options are ignored.
  #
  # Additional query options:
  # @option opts :order [Symbol|String] The session event created_at sort order.
  #   Valid values: :asc, :desc, 'asc' or 'desc'. Default: :desc
  # @option opts :limit [Integer] The maximum number of session events that will be retrieved from the query.
  #   Default: 100
  # @option opts :offset [Integer] The number of session events the query will begin reading from the start
  #   of the set. Default: 0
  # @option opts :search_term [String] Search regular expression used to filter results.
  #   All fields are converted to strings and results are returned if the pattern is matched.
  # @return [Array<Mdm::SessionEvent>|Mdm::SessionEvent::ActiveRecord_Relation] session events that are matched.
  def session_events(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      # If we have the ID, there is no point in creating a complex query.
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Mdm::SessionEvent.find(opts[:id]))
      end

      # Passing workspace keys to the search will cause exceptions, so remove them if they were accidentally included.
      opts.delete(:workspace)

      order = opts.delete(:order)
      order = order.nil? ? DEFAULT_ORDER : order.to_sym

      limit = opts.delete(:limit) || DEFAULT_LIMIT
      offset = opts.delete(:offset) || DEFAULT_OFFSET

      search_term = opts.delete(:search_term)
      results = Mdm::SessionEvent.where(opts).order(created_at: order).offset(offset).limit(limit)

      if search_term && !search_term.empty?
        re_search_term = /#{search_term}/mi
        results = results.select { |event|
          event.attribute_names.any? { |a| event[a.intern].to_s.match(re_search_term) }
        }
      end
      results
    }
  end

  #
  # Record a session event in the database
  #
  # opts MUST contain one of:
  # +:session+:: the Msf::Session, Mdm::Session or Hash representation of Mdm::Session we are reporting
  # +:etype+::   event type, enum: command, output, upload, download, filedelete
  #
  # opts may contain
  # +:output+::      the data for an output event
  # +:command+::     the data for an command event
  # +:remote_path+:: path to the associated file for upload, download, and filedelete events
  # +:local_path+::  path to the associated file for upload, and download
  #
  def report_session_event(opts)
    return if not active
    raise ArgumentError.new("Missing required option :session") if opts[:session].nil?
    raise ArgumentError.new("Expected an :etype") unless opts[:etype]
    session = nil

  ::ActiveRecord::Base.connection_pool.with_connection {
    if opts[:session].respond_to? :db_record
      session = opts[:session].db_record
      if session.nil?
        # The session doesn't have a db_record which means
        #  a) the database wasn't connected at session registration time
        # or
        #  b) something awful happened and the report_session call failed
        #
        # Either way, we can't do anything with this session as is, so
        # log a warning and punt.
        wlog("Warning: trying to report a session_event for a session with no db_record (#{opts[:session].sid})")
        return
      end
      event_data = { :created_at => Time.now }
    else
      session = opts[:session]
      event_data = { :created_at => opts[:created_at] }
    end

    session_id = nil
    if session.is_a?(Mdm::Session)
      session_id = session.id
    elsif session.is_a?(Hash) && session.key?(:id)
      session_id = session[:id]
    end

    event_data[:session_id] = session_id
    [:remote_path, :local_path, :output, :command, :etype].each do |attr|
      event_data[attr] = opts[attr] if opts[attr]
    end

    s = ::Mdm::SessionEvent.create(event_data)
  }
  end
end
