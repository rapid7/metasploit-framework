module Msf::DBManager::Cred
  # This methods returns a list of all credentials in the database
  def creds(opts)
    query = nil
    ::ActiveRecord::Base.connection_pool.with_connection {
      # If :id exists we're looking for a specific record, skip the other stuff
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Metasploit::Credential::Core.find(opts[:id]))
      end

      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
      search_term = opts.delete(:search_term)

      query = Metasploit::Credential::Core.where( workspace_id: wspace.id )
      query = query.includes(:private, :public, :logins, :realm).references(:private, :public, :logins, :realm)
      query = query.includes(logins: [ :service, { service: :host } ])

      if opts[:type].present?
        query = query.where(metasploit_credential_privates: { type: opts[:type] })
      end

      if opts[:svcs].present?
        query = query.where(Mdm::Service[:name].in(opts[:svcs]))
      end

      if opts[:ports].present?
        query = query.where(Mdm::Service[:port].in(opts[:ports]))
      end

      if opts[:user].present?
        # If we have a user regex, only include those that match
        query = query.where('"metasploit_credential_publics"."username" = ?', opts[:user])
      end

      if opts[:pass].present?
        # If we have a password regex, only include those that match
        query = query.where('"metasploit_credential_privates"."data" = ?', opts[:pass])
      end

      if opts[:host_ranges] || opts[:ports] || opts[:svcs]
        # Only find Cores that have non-zero Logins if the user specified a
        # filter based on host, port, or service name
        query = query.where(Metasploit::Credential::Login[:id].not_eq(nil))
      end

      if search_term && !search_term.empty?
        core_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Metasploit::Credential::Core, search_term, ['created_at', 'updated_at'])
        public_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Metasploit::Credential::Public, search_term, ['created_at', 'updated_at'])
        private_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Metasploit::Credential::Private, search_term, ['created_at', 'updated_at'])
        realm_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Metasploit::Credential::Realm, search_term, ['created_at', 'updated_at'])
        column_search_conditions = core_search_conditions.or(public_search_conditions).or(private_search_conditions).or(realm_search_conditions)
        query = query.where(column_search_conditions)
      end
    }
    query
  end

  # This method iterates the creds table calling the supplied block with the
  # cred instance of each entry.
  def each_cred(wspace=framework.db.workspace,&block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.creds.each do |cred|
      block.call(cred)
    end
  }
  end

  # Find or create a credential matching this type/data
  def find_or_create_cred(opts)
    report_auth_info(opts)
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

    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    # Service management; assume the user knows what
    # he's talking about.
    service = opts.delete(:service) || report_service(:host => host, :port => port, :proto => proto, :name => sname, :workspace => wspace)

    # Non-US-ASCII usernames are tripping up the database at the moment, this is a temporary fix until we update the tables
    if (token[0])
      # convert the token to US-ASCII from UTF-8 to prevent an error
      token[0] = token[0].unpack("C*").pack("C*")
      token[0] = token[0].gsub(/[\x00-\x1f\x7f-\xff]/n){|m| "\\x%.2x" % m.unpack("C")[0] }
    end

    if (token[1])
      token[1] = token[1].unpack("C*").pack("C*")
      token[1] = token[1].gsub(/[\x00-\x1f\x7f-\xff]/n){|m| "\\x%.2x" % m.unpack("C")[0] }
    end

    ret = {}

    # Check to see if the creds already exist. We look also for a downcased username with the
    # same password because we can fairly safely assume they are not in fact two separate creds.
    # this allows us to hedge against duplication of creds in the DB.

    if duplicate_ok
    # If duplicate usernames are okay, find by both user and password (allows
    # for actual duplicates to get modified updated_at, sources, etc)
      if token[0].nil? or token[0].empty?
        cred = service.creds.where(user: token[0] || "", ptype: ptype, pass: token[1] || "").first_or_initialize
      else
        cred = service.creds.find_by_user_and_ptype_and_pass(token[0] || "", ptype, token[1] || "")
        unless cred
          dcu = token[0].downcase
          cred = service.creds.find_by_user_and_ptype_and_pass( dcu || "", ptype, token[1] || "")
          unless cred
            cred = service.creds.where(user: token[0] || "", ptype: ptype, pass: token[1] || "").first_or_initialize
          end
        end
      end
    else
      # Create the cred by username only (so we can change passwords)
      if token[0].nil? or token[0].empty?
        cred = service.creds.where(user: token[0] || "", ptype: ptype).first_or_initialize
      else
        cred = service.creds.find_by_user_and_ptype(token[0] || "", ptype)
        unless cred
          dcu = token[0].downcase
          cred = service.creds.find_by_user_and_ptype_and_pass( dcu || "", ptype, token[1] || "")
          unless cred
            cred = service.creds.where(user: token[0] || "", ptype: ptype).first_or_initialize
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

  def update_credential(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      # process workspace string for update if included in opts
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts[:workspace] = wspace if wspace

      if opts[:public]
        if opts[:public][:id]
          public_id = opts[:public].delete(:id)
          public = Metasploit::Credential::Public.find(public_id)
          public.update_attributes(opts[:public])
        else
          public = Metasploit::Credential::Public.where(opts[:public]).first_or_initialize
        end
        opts[:public] = public
      end
      if opts[:private]
        if opts[:private][:id]
          private_id = opts[:private].delete(:id)
          private = Metasploit::Credential::Private.find(private_id)
          private.update_attributes(opts[:private])
        else
          private = Metasploit::Credential::Private.where(opts[:private]).first_or_initialize
        end
        opts[:private] = private
      end
      if opts[:origin]
        if opts[:origin][:id]
          origin_id = opts[:origin].delete(:id)
          origin = Metasploit::Credential::Origin.find(origin_id)
          origin.update_attributes(opts[:origin])
        else
          origin = Metasploit::Credential::Origin.where(opts[:origin]).first_or_initialize
        end
        opts[:origin] = origin
      end

      id = opts.delete(:id)
      cred = Metasploit::Credential::Core.find(id)
      cred.update!(opts)
      return cred
    }
  end

  def delete_credentials(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection {
      deleted = []
      opts[:ids].each do |cred_id|
        cred = Metasploit::Credential::Core.find(cred_id)
        begin
          deleted << cred.destroy
        rescue # refs suck
          elog("Forcibly deleting #{cred}")
          deleted << cred.delete
        end
      end

      return deleted
    }
  end

  alias :report_auth :report_auth_info
  alias :report_cred :report_auth_info
end
