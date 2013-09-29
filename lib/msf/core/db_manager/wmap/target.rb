module Msf::DBManager::WMAP::Target
  def selected_host
    with_connection {
      selhost = ::Mdm::WmapTarget.where("selected != 0").first()
      if selhost
        return selhost.host
      else
        return
      end
    }
  end

  #
  # WMAP
  # This method iterates the targets table calling the supplied block with the
  # target instance of each entry.
  #
  def each_target(&block)
    targets.each do |target|
      block.call(target)
    end
  end

  #
  # WMAP
  # This methods returns a list of all targets in the database
  #
  def targets
    with_connection {
      ::Mdm::WmapTarget.find(:all)
    }
  end

  #
  # WMAP
  # This methods deletes all targets from targets table in the database
  #
  def delete_all_targets
    with_connection {
      ::Mdm::WmapTarget.delete_all
    }
  end

  #
  # WMAP
  # Find a target matching this id
  #
  def get_target(id)
    with_connection {
      target = ::Mdm::WmapTarget.where("id = ?", id).first()
      return target
    }
  end

  #
  # WMAP
  # Create a target
  #
  def create_target(host,port,ssl,sel)
    with_connection {
      tar = ::Mdm::WmapTarget.create(
          :host => host,
          :address => host,
          :port => port,
          :ssl => ssl,
          :selected => sel
      )
      #framework.events.on_db_target(rec)
    }
  end

  #
  # WMAP
  # Selected target
  #
  def selected_wmap_target
    with_connection {
      ::Mdm::WmapTarget.find.where("selected != 0")
    }
  end

  #
  # WMAP
  # Selected port
  #
  def selected_port
    selected_wmap_target.port
  end

  #
  # WMAP
  # Selected ssl
  #
  def selected_ssl
    selected_wmap_target.ssl
  end

  #
  # WMAP
  # Selected id
  #
  def selected_id
    selected_wmap_target.object_id
  end
end
