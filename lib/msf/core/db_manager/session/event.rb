module Msf::DBManager::Session::Event
  #
  # Record a session event in the database
  #
  # opts MUST contain one of:
  # +:session+:: the Msf::Session OR the ::Mdm::Session we are reporting
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

      event_data[:session_id] = session.id
      [:remote_path, :local_path, :output, :command, :etype].each do |attr|
        event_data[attr] = opts[attr] if opts[attr]
      end

      s = ::Mdm::SessionEvent.create(event_data)
    }
  end
end