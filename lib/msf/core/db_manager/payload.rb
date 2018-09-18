module Msf::DBManager::Payload

  def create_payload(opts)
    Mdm::Payload.create(opts)
  end

  def payloads(opts)
    ::ActiveRecord::Base.connection_pool.with_connection do
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Mdm::Payload.find(opts[:id]))
      end

      return Mdm::Payload.where(opts)
    end
  end

  def payload_count
    ::ActiveRecord::Base.connection_pool.with_connection do
      Mdm::Payload.count
    end
  end

  def update_payload(opts)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts[:workspace] = wspace if wspace

      id = opts.delete(:id)
      Mdm::Payload.update(id, opts)
    end
  end

  def delete_payload(opts)
    raise ArgumentError.new("The following options are required: :uuids") if opts[:uuids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection do
      deleted = []
      opts[:uuids].each do |uuid|
        payload = Mdm::Payload.find_by(uuid: uuid)
        begin
          deleted << payload.destroy
        rescue # refs suck
          elog("Forcibly deleting #{payload.address}")
          deleted << payload.delete
        end
      end

      return deleted
    end
  end

end
