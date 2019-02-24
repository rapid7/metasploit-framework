module Msf::DBManager::Ref
  #
  # Find or create a reference matching this name
  #
  def find_or_create_ref(opts)
    ret = {}
    ret[:ref] = get_ref(opts[:name])
    return ret[:ref] if ret[:ref]

  ::ActiveRecord::Base.connection_pool.with_connection {
    ref = ::Mdm::Ref.where(name: opts[:name]).first_or_initialize

    begin
      framework.events.on_db_ref(ref) if ref
    rescue ::Exception => e
      wlog("Exception in on_db_ref event handler: #{e.class}: #{e}")
      wlog("Call Stack\n#{e.backtrace.join("\n")}")
    end

    if ref and ref.changed?
      ref.save!
    end
    ret[:ref] = ref
  }
  end

  def get_ref(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Ref.find_by_name(name)
  }
  end

  #
  # Find a reference matching this name
  #
  def has_ref?(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    Mdm::Ref.find_by_name(name)
  }
  end
end