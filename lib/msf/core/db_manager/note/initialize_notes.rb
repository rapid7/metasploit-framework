
module Msf::DBManager::Note::InitializeNotes
  def initialize_note(opts)
    return if not active
    ::ApplicationRecord.connection_pool.with_connection {
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
      opts = opts.clone()
      opts.delete(:workspace)
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
            # XXX: These normalizations are lazy af
          when 'http', 'smb'
            proto = 'tcp'
            sname = proto_lower
          when 'dns','snmp','dhcp'
            proto = 'udp'
            sname = proto_lower
          else
            proto = 'tcp'
            sname = proto_lower
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


      if addr && !host
        host = get_host(:workspace => wspace, :host => addr)
      end
      if host && (opts[:port] && proto)
        # only one result can be returned, as the +port+ field restricts potential results to a single service
        service = services(:workspace => wspace,
                           :hosts => {address: host.address},
                           :proto => proto,
                           :port => opts[:port]).first
      elsif opts[:service] && opts[:service].kind_of?(::Mdm::Service)
        service = opts[:service]
      end

      ntype  = opts.delete(:type) || opts.delete(:ntype) || (raise RuntimeError, "A note :type or :ntype is required")
      data   = opts[:data]
      note   = nil
      conditions = { :ntype => ntype }
      conditions[:host_id] = host[:id] if host
      conditions[:service_id] = service[:id] if service
      conditions[:vuln_id] = opts[:vuln_id]

      case mode.to_sym
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
        unless note
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
        if opts[:service] && opts[:service].kind_of?(::Mdm::Service)
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
      note
    }
  end
end
