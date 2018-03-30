module Msf::DBManager::Note
  #
  # This method iterates the notes table calling the supplied block with the
  # note instance of each entry.
  #
  def each_note(wspace=workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.notes.each do |note|
      block.call(note)
    end
  }
  end

  #
  # Find or create a note matching this type/data
  #
  def find_or_create_note(opts)
    report_note(opts)
  end

  #
  # This methods returns a list of all notes in the database
  #
  def notes(opts)
    wspace = opts.delete(:workspace) || opts.delete(:wspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end

    ::ActiveRecord::Base.connection_pool.with_connection {

      search_term = opts.delete(:search_term)
      if search_term && !search_term.empty?
        all_columns_except_data_expression = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Note, search_term, ["data"])

        # The data column is serialized so an Arel regex-based search is created following
        # somewhat from the Mdm search scope. If data appears to be serialized it is decoded for the regex match.
        # The Mdm search scope used 'BAh7%' which doesn't appears to result in matches against simple string
        # values that have been serialized, so this was changed to 'BAh%'. The decoded binary data is then
        # converted to a text value to be used for the regex match.
        serialized_prefix = 'BAh%'
        re_search_term = "(?mi)#{search_term}"
        arel_table = Mdm::Note.arel_table
        regex_data = Arel::Nodes::Regexp.new(arel_table[:data], Arel::Nodes.build_quoted(re_search_term))
        data_no_base64_expression = arel_table.grouping(arel_table[:data].does_not_match(serialized_prefix).and(regex_data))

        decode_func = Arel::Nodes::NamedFunction.new("decode", [arel_table[:data], Arel::Nodes.build_quoted('base64')])
        convert_from_func = Arel::Nodes::NamedFunction.new("convert_from", [decode_func, Arel::Nodes.build_quoted('UTF8')])
        regex_data_base64 = Arel::Nodes::Regexp.new(convert_from_func, Arel::Nodes.build_quoted(re_search_term))
        data_base64_expression = arel_table.grouping(arel_table[:data].matches(serialized_prefix).and(regex_data_base64))

        data_column_expression = data_no_base64_expression.or(data_base64_expression)
        column_search_expression = all_columns_except_data_expression.or(data_column_expression)
        wspace.notes.includes(:host).where(opts).where(column_search_expression)
      else
        wspace.notes.includes(:host).where(opts)
      end
    }
  end

  #
  # Report a Note to the database.  Notes can be tied to a ::Mdm::Workspace, Host, or Service.
  #
  # opts MUST contain
  # +:type+::  The type of note, e.g. smb_peer_os
  #
  # opts can contain
  # +:workspace+::  the workspace to associate with this Note
  # +:host+::       an IP address or a Host object to associate with this Note
  # +:service+::    a Service object to associate with this Note
  # +:data+::       whatever it is you're making a note of
  # +:port+::       along with +:host+ and +:proto+, a service to associate with this Note
  # +:proto+::      along with +:host+ and +:port+, a service to associate with this Note
  # +:update+::     what to do in case a similar Note exists, see below
  #
  # The +:update+ option can have the following values:
  # +:unique+::       allow only a single Note per +:host+/+:type+ pair
  # +:unique_data+::  like +:uniqe+, but also compare +:data+
  # +:insert+::       always insert a new Note even if one with identical values exists
  #
  # If the provided +:host+ is an IP address and does not exist in the
  # database, it will be created.  If +:workspace+, +:host+ and +:service+
  # are all omitted, the new Note will be associated with the current
  # workspace.
  #
  def report_note(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end
    seen = opts.delete(:seen) || false
    crit = opts.delete(:critical) || false
    host = nil
    addr = nil
    # Report the host so it's there for the Proc to use below
    if opts[:host]
      if opts[:host].kind_of? ::Mdm::Host
        host = opts[:host]
      else
        addr = Msf::Util::Host.normalize_host(opts[:host])
        host = report_host({:workspace => wspace, :host => addr})
      end
      # Do the same for a service if that's also included.
      if (opts[:port])
        proto = nil
        sname = nil
        proto_lower = opts[:proto].to_s.downcase # Catch incorrect usages
        case proto_lower
        when 'tcp','udp'
          proto = proto_lower
          sname = opts[:sname] if opts[:sname]
        when 'dns','snmp','dhcp'
          proto = 'udp'
          sname = opts[:proto]
        else
          proto = 'tcp'
          sname = opts[:proto]
        end
        sopts = {
          :workspace => wspace,
          :host  => host,
          :port  => opts[:port],
          :proto => proto
        }
        sopts[:name] = sname if sname
        report_service(sopts)
      end
    end
    # Update Modes can be :unique, :unique_data, :insert
    mode = opts[:update] || :unique

    ret = {}

    if addr and not host
      host = get_host(:workspace => wspace, :host => addr)
    end
    if host and (opts[:port] and opts[:proto])
      service = get_service(wspace, host, opts[:proto], opts[:port])
    elsif opts[:service] and opts[:service].kind_of? ::Mdm::Service
      service = opts[:service]
    end
=begin
    if host
      host.updated_at = host.created_at
      host.state      = HostState::Alive
      host.save!
    end
=end
    ntype  = opts.delete(:type) || opts.delete(:ntype) || (raise RuntimeError, "A note :type or :ntype is required")
    data   = opts[:data]
    note   = nil

    conditions = { :ntype => ntype }
    conditions[:host_id] = host[:id] if host
    conditions[:service_id] = service[:id] if service
    conditions[:vuln_id] = opts[:vuln_id]

    case mode
    when :unique
      note      = wspace.notes.where(conditions).first_or_initialize
      note.data = data
    when :unique_data
      notes = wspace.notes.where(conditions)

      # Don't make a new Note with the same data as one that already
      # exists for the given: type and (host or service)
      notes.each do |n|
        # Compare the deserialized data from the table to the raw
        # data we're looking for.  Because of the serialization we
        # can't do this easily or reliably in SQL.
        if n.data == data
          note = n
          break
        end
      end
      if not note
        # We didn't find one with the data we're looking for, make
        # a new one.
        note = wspace.notes.new(conditions.merge(:data => data))
      end
    else
      # Otherwise, assume :insert, which means always make a new one
      note = wspace.notes.new
      if host
        note.host_id = host[:id]
      end
      if opts[:service] and opts[:service].kind_of? ::Mdm::Service
        note.service_id = opts[:service][:id]
      end
      note.seen     = seen
      note.critical = crit
      note.ntype    = ntype
      note.data     = data
    end
    if opts[:vuln_id]
      note.vuln_id = opts[:vuln_id]
    end
    msf_import_timestamps(opts,note)
    note.save!
    ret[:note] = note
  }
  end

  # Update the attributes of a note entry with the values in opts.
  # The values in opts should match the attributes to update.
  #
  # @param opts [Hash] Hash containing the updated values. Key should match the attribute to update. Must contain :id of record to update.
  # @return [Mdm::Note] The updated Mdm::Note object.
  def update_note(opts)
    # process workspace string for update if included in opts
    wspace = opts.delete(:workspace)
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
      opts[:workspace] = wspace
    end

    ::ActiveRecord::Base.connection_pool.with_connection {
      id = opts.delete(:id)
      Mdm::Note.update(id, opts)
    }
  end

  # Deletes note entries based on the IDs passed in.
  #
  # @param opts[:ids] [Array] Array containing Integers corresponding to the IDs of the note entries to delete.
  # @return [Array] Array containing the Mdm::Note objects that were successfully deleted.
  def delete_note(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection {
      deleted = []
      opts[:ids].each do |note_id|
        note = Mdm::Note.find(note_id)
        begin
          deleted << note.destroy
        rescue # refs suck
          elog("Forcibly deleting #{note}")
          deleted << note.delete
        end
      end

      return deleted
    }
  end
end
