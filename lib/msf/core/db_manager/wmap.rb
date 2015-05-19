# @note Wmap is a plugin and so these methods, that are only meant for that plugin, should not be part of the core
#   library.
module Msf::DBManager::WMAP
  # Create a request (by hand)
  def create_request(host,port,ssl,meth,path,headers,query,body,respcode,resphead,response)
  ::ActiveRecord::Base.connection_pool.with_connection {
    req = ::Mdm::WmapRequest.create(
        :host => host,
        :address => host,
        :port => port,
        :ssl => ssl,
        :meth => meth,
        :path => path,
        :headers => headers,
        :query => query,
        :body => body,
        :respcode => respcode,
        :resphead => resphead,
        :response => response
      )
    #framework.events.on_db_request(rec)
  }
  end

  # Create a target
  def create_target(host,port,ssl,sel)
  ::ActiveRecord::Base.connection_pool.with_connection {
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

  # This methods deletes all targets from targets table in the database
  def delete_all_targets
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapTarget.delete_all
  }
  end

  # This method iterates the requests table identifying possible targets
  # This method will be removed on second phase of db merging.
  def each_distinct_target(&block)
    request_distinct_targets.each do |target|
      block.call(target)
    end
  end

  # This method iterates the requests table calling the supplied block with the
  # request instance of each entry.
  def each_request(&block)
    requests.each do |request|
      block.call(request)
    end
  end

  # This method iterates the requests table returning a list of all requests of a specific target
  def each_request_target(&block)
    target_requests('').each do |req|
      block.call(req)
    end
  end

  # This method iterates the requests table returning a list of all requests of a specific target
  def each_request_target_with_body(&block)
    target_requests('AND wmap_requests.body IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  # This method iterates the requests table returning a list of all requests of a specific target
  def each_request_target_with_headers(&block)
    target_requests('AND wmap_requests.headers IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  # This method iterates the requests table returning a list of all requests of a specific target
  def each_request_target_with_path(&block)
    target_requests('AND wmap_requests.path IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  # This method iterates the requests table returning a list of all requests of a specific target
  def each_request_target_with_query(&block)
    target_requests('AND wmap_requests.query IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  # This method iterates the targets table calling the supplied block with the
  # target instance of each entry.
  def each_target(&block)
    targets.each do |target|
      block.call(target)
    end
  end

  # Find a target matching this id
  def get_target(id)
  ::ActiveRecord::Base.connection_pool.with_connection {
    target = ::Mdm::WmapTarget.where("id = ?", id).first()
    return target
  }
  end

  # This method returns a list of all possible targets available in requests
  # This method will be removed on second phase of db merging.
  def request_distinct_targets
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapRequest.select('DISTINCT host,address,port,ssl')
  }
  end

  # This method allows to query directly the requests table. To be used mainly by modules
  def request_sql(host,port,extra_condition)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapRequest.where("wmap_requests.host = ? AND wmap_requests.port = ? #{extra_condition}", host , port)
  }
  end

  # This methods returns a list of all targets in the database
  def requests
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapRequest.all
  }
  end

  # Selected host
  def selected_host
  ::ActiveRecord::Base.connection_pool.with_connection {
    selhost = ::Mdm::WmapTarget.where("selected != 0").first()
    if selhost
      return selhost.host
    else
      return
    end
  }
  end

  # Selected id
  def selected_id
    selected_wmap_target.object_id
  end

  # Selected port
  def selected_port
    selected_wmap_target.port
  end

  # Selected ssl
  def selected_ssl
    selected_wmap_target.ssl
  end

  # Selected target
  def selected_wmap_target
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapTarget.find.where("selected != 0")
  }
  end

  # Quick way to query the database (used by wmap_sql)
  def sql_query(sqlquery)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ActiveRecord::Base.connection.select_all(sqlquery)
  }
  end

  # This method returns a list of all requests from target
  def target_requests(extra_condition)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapRequest.where("wmap_requests.host = ? AND wmap_requests.port = ? #{extra_condition}",selected_host,selected_port)
  }
  end

  # This methods returns a list of all targets in the database
  def targets
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapTarget.all
  }
  end
end
