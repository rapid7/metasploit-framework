module Msf::DBManager::Payload

  def create_payload(opts)
    ::ApplicationRecord.connection_pool.with_connection do
      if opts[:uuid] && !opts[:uuid].to_s.empty?
        if Mdm::Payload.find_by(uuid: opts[:uuid])
          raise ArgumentError.new("A payload with this uuid already exists.")
        end
      end

      Mdm::Payload.create!(opts)
    end
  end

  def payloads(opts)
    ::ApplicationRecord.connection_pool.with_connection do
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Mdm::Payload.find(opts[:id]))
      else
        # Check the database for a matching UUID, returning an empty array if no results are found
        begin
          return Array.wrap(Mdm::Payload.where(uuid: opts[:uuid]))
        rescue ActiveRecord::RecordNotFound
          return []
        end
      end
    end
  end

  def update_payload(opts)
    ::ApplicationRecord.connection_pool.with_connection do
      opts = opts.clone() # protect the original caller's opts
      id = opts.delete(:id)
      Mdm::Payload.update(id, opts)
    end
  end

  def delete_payload(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ApplicationRecord.connection_pool.with_connection do
      deleted = []
      opts[:ids].each do |payload_id|
        payload = Mdm::Payload.find(payload_id)
        begin
          deleted << payload.destroy
        rescue
          elog("Forcibly deleting #{payload}")
          deleted << payload.delete
        end
      end

      return deleted
    end
  end

  def get_payload(opts)
    raise ArgumentError.new("The following options are required: :uuid") if opts[:uuid].nil?

    ::ApplicationRecord.connection_pool.with_connection do
      return Mdm::Payload.find_by(uuid: opts[:uuid])
    end

  end

end
