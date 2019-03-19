module Msf::DBManager::AsyncCallback

  def create_async_callback(opts)
    ::ActiveRecord::Base.connection_pool.with_connection do
      # Disabled UUID checking, since we anticipate multiple callbacks from the same UUID
      #if opts[:uuid] && !opts[:uuid].to_s.empty?
      #  if Mdm::AsyncCallback.find_by(uuid: opts[:uuid])
      #    raise ArgumentError.new("An async callback with this uuid already exists.")
      #  end
      #end

      Mdm::AsyncCallback.create!(opts)
    end
  end

  def async_callbacks(opts)
    ::ActiveRecord::Base.connection_pool.with_connection do
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Mdm::AsyncCallback.find(opts[:id]))
      end

      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
      return wspace.async_callbacks.where(opts)
    end
  end

  def update_async_callback(opts)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts[:workspace] = wspace if wspace

      id = opts.delete(:id)
      Mdm::AsyncCallback.update(id, opts)
    end
  end

end
