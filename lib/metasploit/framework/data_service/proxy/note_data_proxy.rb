module NoteDataProxy

  def notes(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.notes(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving notes")
    end
  end

  def find_or_create_note(opts)
    begin
      # create separate opts for find operation since the report operation uses slightly different keys
      # TODO: standardize option keys used for the find and report operations
      find_opts = opts.clone
      # convert type to ntype
      find_opts[:ntype] = find_opts.delete(:type) if find_opts.key?(:type)
      # convert host to nested hosts address
      find_opts[:hosts] = {address: find_opts.delete(:host)} if find_opts.key?(:host)

      note = notes(find_opts)
      if note.nil? || note.first.nil?
        note = report_note(opts.clone)
      else
        note = note.first
      end
      note
    rescue => e
      self.log_error(e, "Problem finding or creating note")
    end
  end

  def report_note(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_note(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting note")
    end
  end

  def update_note(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.update_note(opts)
      end
    rescue => e
      self.log_error(e, "Problem updating note")
    end
  end

  def delete_note(opts)
    begin
      self.data_service_operation do |data_service|
        data_service.delete_note(opts)
      end
    rescue => e
      self.log_error(e, "Problem deleting note")
    end
  end
end