module SessionEventDataProxy

  def session_events
    begin
      data_service = self.get_data_service()
      puts "In SessionEventDataProxy.session_events"
    rescue  Exception => e
      puts"Call to  #{data_service.class}#session_events threw exception: #{e.message}"
    end
  end

  def report_session_event(opts)
    begin
      data_service = self.get_data_service()

      # TODO: This is pretty hacky, but I don't want to change the code in Msf::DBManager::SessionEvent at this time.
      # If we decide it's ok to make changes in that code then we need to make it simply store the object and
      # do the pre-processing here.
      if !data_service.is_a?(Msf::DBManager)
        # The Msf::DBManager::SessionEvent.report_session_event does a lot of work for creating the SessionEvent
        # Should we move that here?
        #opts[:session] = opts[:session].sid
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
        opts = event_data
      end

      data_service.report_session_event(opts)
    rescue Exception => e
      puts "Call to #{data_service.class}#report_session_event threw exception: #{e.message}"
    end
  end
end