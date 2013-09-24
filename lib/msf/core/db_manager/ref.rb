module Msf::DBManager::Ref
  #
  # Find a reference matching this name
  #
  def has_ref?(name)
    ::ActiveRecord::Base.connection_pool.with_connection {
      Mdm::Ref.find_by_name(name)
    }
  end

  #
  # Find or create a reference matching this name
  #
  def find_or_create_ref(opts)
    ret = {}
    ret[:ref] = get_ref(opts[:name])
    return ret[:ref] if ret[:ref]

    ::ActiveRecord::Base.connection_pool.with_connection {
      ref = ::Mdm::Ref.find_or_initialize_by_name(opts[:name])
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
end