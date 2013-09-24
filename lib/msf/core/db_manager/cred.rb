module Msf::DBManager::Cred
  #
  # This methods returns a list of all credentials in the database
  #
  def creds(wspace=workspace)
    ::ActiveRecord::Base.connection_pool.with_connection {
      Mdm::Cred.includes({:service => :host}).where("hosts.workspace_id = ?", wspace.id)
    }
  end

  #
  # Store a set of credentials in the database.
  #
  # report_auth_info used to create a note, now it creates
  # an entry in the creds table. It's much more akin to
  # report_vuln() now.
  #
  # opts MUST contain
  # +:host+::   an IP address or Host object reference
  # +:port+::   a port number
  #
  # opts can contain
  # +:user+::   the username
  # +:pass+::   the password, or path to ssh_key
  # +:ptype+::  the type of password (password(ish), hash, or ssh_key)
  # +:proto+::  a transport name for the port
  # +:sname+::  service name
  # +:active+:: by default, a cred is active, unless explicitly false
  # +:proof+::  data used to prove the account is actually active.
  #
  # Sources: Credentials can be sourced from another credential, or from
  # a vulnerability. For example, if an exploit was used to dump the
  # smb_hashes, and this credential comes from there, the source_id would
  # be the Vuln id (as reported by report_vuln) and the type would be "Vuln".
  #
  # +:source_id+::   The Vuln or Cred id of the source of this cred.
  # +:source_type+:: Either Vuln or Cred
  #
  # TODO: This is written somewhat host-centric, when really the
  # Service is the thing. Need to revisit someday.
  def report_auth_info(opts={})
    return if not active
    raise ArgumentError.new("Missing required option :host") if opts[:host].nil?
    raise ArgumentError.new("Missing required option :port") if (opts[:port].nil? and opts[:service].nil?)

    if (not opts[:host].kind_of?(::Mdm::Host)) and (not validate_ips(opts[:host]))
      raise ArgumentError.new("Invalid address or object for :host (#{opts[:host].inspect})")
    end

    ::ActiveRecord::Base.connection_pool.with_connection {
      host = opts.delete(:host)
      ptype = opts.delete(:type) || "password"
      token = [opts.delete(:user), opts.delete(:pass)]
      sname = opts.delete(:sname)
      port = opts.delete(:port)
      proto = opts.delete(:proto) || "tcp"
      proof = opts.delete(:proof)
      source_id = opts.delete(:source_id)
      source_type = opts.delete(:source_type)
      duplicate_ok = opts.delete(:duplicate_ok)
      # Nil is true for active.
      active = (opts[:active] || opts[:active].nil?) ? true : false

      wspace = opts.delete(:workspace) || workspace

      # Service management; assume the user knows what
      # he's talking about.
      service = opts.delete(:service) || report_service(:host => host, :port => port, :proto => proto, :name => sname, :workspace => wspace)

      # Non-US-ASCII usernames are tripping up the database at the moment, this is a temporary fix until we update the tables
      if (token[0])
        # convert the token to US-ASCII from UTF-8 to prevent an error
        token[0] = token[0].unpack("C*").pack("C*")
        token[0] = token[0].gsub(/[\x00-\x1f\x7f-\xff]/){|m| "\\x%.2x" % m.unpack("C")[0] }
      end

      if (token[1])
        token[1] = token[1].unpack("C*").pack("C*")
        token[1] = token[1].gsub(/[\x00-\x1f\x7f-\xff]/){|m| "\\x%.2x" % m.unpack("C")[0] }
      end

      ret = {}

      #Check to see if the creds already exist. We look also for a downcased username with the
      #same password because we can fairly safely assume they are not in fact two seperate creds.
      #this allows us to hedge against duplication of creds in the DB.

      if duplicate_ok
        # If duplicate usernames are okay, find by both user and password (allows
        # for actual duplicates to get modified updated_at, sources, etc)
        if token[0].nil? or token[0].empty?
          cred = service.creds.find_or_initialize_by_user_and_ptype_and_pass(token[0] || "", ptype, token[1] || "")
        else
          cred = service.creds.find_by_user_and_ptype_and_pass(token[0] || "", ptype, token[1] || "")
          unless cred
            dcu = token[0].downcase
            cred = service.creds.find_by_user_and_ptype_and_pass( dcu || "", ptype, token[1] || "")
            unless cred
              cred = service.creds.find_or_initialize_by_user_and_ptype_and_pass(token[0] || "", ptype, token[1] || "")
            end
          end
        end
      else
        # Create the cred by username only (so we can change passwords)
        if token[0].nil? or token[0].empty?
          cred = service.creds.find_or_initialize_by_user_and_ptype(token[0] || "", ptype)
        else
          cred = service.creds.find_by_user_and_ptype(token[0] || "", ptype)
          unless cred
            dcu = token[0].downcase
            cred = service.creds.find_by_user_and_ptype_and_pass( dcu || "", ptype, token[1] || "")
            unless cred
              cred = service.creds.find_or_initialize_by_user_and_ptype(token[0] || "", ptype)
            end
          end
        end
      end

      # Update with the password
      cred.pass = (token[1] || "")

      # Annotate the credential
      cred.ptype = ptype
      cred.active = active

      # Update the source ID only if there wasn't already one.
      if source_id and !cred.source_id
        cred.source_id = source_id
        cred.source_type = source_type if source_type
      end

      # Safe proof (lazy way) -- doesn't chop expanded
      # characters correctly, but shouldn't ever be a problem.
      unless proof.nil?
        proof = Rex::Text.to_hex_ascii(proof)
        proof = proof[0,4096]
      end
      cred.proof = proof

      # Update the timestamp
      if cred.changed?
        msf_import_timestamps(opts,cred)
        cred.save!
      end

      # Ensure the updated_at is touched any time report_auth_info is called
      # except when it's set explicitly (as it is for imports)
      unless opts[:updated_at] || opts["updated_at"]
        cred.updated_at = Time.now.utc
        cred.save!
      end


      if opts[:task]
        Mdm::TaskCred.create(
            :task => opts[:task],
            :cred => cred
        )
      end

      ret[:cred] = cred
    }
  end

  alias :report_cred :report_auth_info
  alias :report_auth :report_auth_info

  #
  # Find or create a credential matching this type/data
  #
  def find_or_create_cred(opts)
    report_auth_info(opts)
  end

  #
  # This method iterates the creds table calling the supplied block with the
  # cred instance of each entry.
  #
  def each_cred(wspace=workspace,&block)
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace.creds.each do |cred|
        block.call(cred)
      end
    }
  end
end