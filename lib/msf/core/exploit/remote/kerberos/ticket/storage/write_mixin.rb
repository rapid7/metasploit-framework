module Msf::Exploit::Remote::Kerberos::Ticket::Storage
  # A mixin providing the ability to store new and delete existing tickets.
  module WriteMixin
    # (see Base#delete_tickets)
    def delete_tickets(options = {})
      if options.keys == [:ids]
        # skip calling #objects which issues a query when the IDs are specified
        ids = options[:ids]
      else
        ids = objects(options).map(&:id)
      end

      framework.db.delete_loot(ids: ids).map do |stored_loot|
        StoredTicket.new(stored_loot)
      end
    end

    # (see Base#store_ccache)
    def store_ccache(ccache, options = {})
      realm = options.fetch(:realm) { ccache.default_principal.realm }
      # use #components.to_a.join('/') to omit the realm that #to_s includes
      client = options.fetch(:client) { ccache.credentials.first&.client&.components.to_a.join('/') }
      server = options.fetch(:server) { ccache.credentials.first&.server&.components.to_a.join('/') }
      info = generate_info_string(realm: realm, client: client, server: server)
      loot = nil
      path = store_loot('mit.kerberos.ccache', 'application/octet-stream', options[:host], ccache.encode, nil, info) do |mdm_loot|
        loot = mdm_loot
      end
      message = ''
      if @framework_module.respond_to?(:peer) && @framework_module.peer.present? && @framework_module.peer != ':'
        message << "#{@framework_module.peer} - "
      end
      if server && server.to_s.downcase.start_with?('krbtgt/')
        message << 'TGT '
      else
        message << 'TGS '
      end
      message << "MIT Credential Cache ticket saved to #{path}"
      print_status(message)

      { path: path, loot: loot }
    end

    # (see Base#deactivate_ccache)
    def deactivate_ccache(ids:)
      set_ccache_status(ids: ids, status: 'inactive')
    end

    # (see Base#activate_ccache)
    def activate_ccache(ids:)
      set_ccache_status(ids: ids, status: 'active')
    end

    private

    # @param [Array<Integer>] ids List of ticket IDs to update
    # @param [String] status The status to set for the tickets
    # @return [Array<StoredTicket>]
    def set_ccache_status(ids:, status:)
      updated_loots = []
      ids.each do |id|
        loot = objects({ id: id })
        if loot.blank?
          print_warning("Ccache with id: #{id} was not found in loot")
          next
        end
        updated_loot_info = update_info_string(loot.first.info, status: status)
        # I know this looks weird but the local db returns a single loot object, remote db returns an array of them
        updated_loots << Array.wrap(framework.db.update_loot({ id: id, info: updated_loot_info })).first
      end
      updated_loots.map do |stored_loot|
        StoredTicket.new(stored_loot)
      end
    end

    def generate_info_string(options = {})
      JSON.generate(loot_info(options))
    end

    def update_info_string(info, **kwargs)
      info_hash = parse_json_no_errors(info)
      updated_hash = loot_info(info_hash.merge(kwargs))
      JSON.generate(updated_hash)
    end

    def parse_json_no_errors(json)
      JSON.parse(json).symbolize_keys
    rescue JSON::ParserError
      wlog('Ccache info is invalid JSON')
      {}
    end
  end
end
