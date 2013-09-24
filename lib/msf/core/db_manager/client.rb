module Msf::DBManager::Client
  def get_client(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace = opts.delete(:workspace) || workspace
      host   = get_host(:workspace => wspace, :host => opts[:host]) || return
      client = host.clients.where({:ua_string => opts[:ua_string]}).first()
      return client
    }
  end

  def find_or_create_client(opts)
    report_client(opts)
  end

  #
  # Report a client running on a host.
  #
  # opts MUST contain
  # +:ua_string+::  the value of the User-Agent header
  # +:host+::       the host where this client connected from, can be an ip address or a Host object
  #
  # opts can contain
  # +:ua_name+::    one of the Msf::HttpClients constants
  # +:ua_ver+::     detected version of the given client
  # +:campaign+::   an id or Campaign object
  #
  # Returns a Client.
  #
  def report_client(opts)
    return if not active
    ::ActiveRecord::Base.connection_pool.with_connection {
      addr = opts.delete(:host) || return
      wspace = opts.delete(:workspace) || workspace
      report_host(:workspace => wspace, :host => addr)

      ret = {}

      host = get_host(:workspace => wspace, :host => addr)
      client = host.clients.find_or_initialize_by_ua_string(opts[:ua_string])

      opts[:ua_string] = opts[:ua_string].to_s

      campaign = opts.delete(:campaign)
      if campaign
        case campaign
          when Campaign
            opts[:campaign_id] = campaign.id
          else
            opts[:campaign_id] = campaign
        end
      end

      opts.each { |k,v|
        if (client.attribute_names.include?(k.to_s))
          client[k] = v
        else
          dlog("Unknown attribute for Client: #{k}")
        end
      }
      if (client and client.changed?)
        client.save!
      end
      ret[:client] = client
    }
  end
end