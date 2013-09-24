module Msf::DBManager::Note
  def report_import_note(wspace,addr)
    if @import_filedata.kind_of?(Hash) && @import_filedata[:filename] && @import_filedata[:filename] !~ /msfe-nmap[0-9]{8}/
      report_note(
          :workspace => wspace,
          :host => addr,
          :type => 'host.imported',
          :data => @import_filedata.merge(:time=> Time.now.utc)
      )
    end
  end

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
          addr = normalize_host(opts[:host])
          host = report_host({:workspace => wspace, :host => addr})
        end
        # Do the same for a service if that's also included.
        if (opts[:port])
          proto = nil
          sname = nil
          case opts[:proto].to_s.downcase # Catch incorrect usages
            when 'tcp','udp'
              proto = opts[:proto]
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
      method = nil
      args   = []
      note   = nil

      conditions = { :ntype => ntype }
      conditions[:host_id] = host[:id] if host
      conditions[:service_id] = service[:id] if service

      case mode
        when :unique
          notes = wspace.notes.where(conditions)

          # Only one note of this type should exist, make a new one if it
          # isn't there. If it is, grab it and overwrite its data.
          if notes.empty?
            note = wspace.notes.new(conditions)
          else
            note = notes[0]
          end
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
      msf_import_timestamps(opts,note)
      note.save!
      ret[:note] = note
    }
  end

  #
  # This methods returns a list of all notes in the database
  #
  def notes(wspace=workspace)
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace.notes
    }
  end
end