module Msf::DBManager::WMAP::Request
  #
  # WMAP
  # Create a request (by hand)
  #
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

  #
  # WMAP
  # This method iterates the requests table identifiying possible targets
  # This method wiil be remove on second phase of db merging.
  #
  def each_distinct_target(&block)
    request_distinct_targets.each do |target|
      block.call(target)
    end
  end

  #
  # WMAP
  # This method returns a list of all possible targets available in requests
  # This method wiil be remove on second phase of db merging.
  #
  def request_distinct_targets
    ::ActiveRecord::Base.connection_pool.with_connection {
      ::Mdm::WmapRequest.select('DISTINCT host,address,port,ssl')
    }
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target_with_path(&block)
    target_requests('AND wmap_requests.path IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target_with_query(&block)
    target_requests('AND wmap_requests.query IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target_with_body(&block)
    target_requests('AND wmap_requests.body IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target_with_headers(&block)
    target_requests('AND wmap_requests.headers IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target(&block)
    target_requests('').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method returns a list of all requests from target
  #
  def target_requests(extra_condition)
    ::ActiveRecord::Base.connection_pool.with_connection {
      ::Mdm::WmapRequest.where("wmap_requests.host = ? AND wmap_requests.port = ? #{extra_condition}",selected_host,selected_port)
    }
  end

  #
  # WMAP
  # This method iterates the requests table calling the supplied block with the
  # request instance of each entry.
  #
  def each_request(&block)
    requests.each do |request|
      block.call(request)
    end
  end

  #
  # WMAP
  # This method allows to query directly the requests table. To be used mainly by modules
  #
  def request_sql(host,port,extra_condition)
    ::ActiveRecord::Base.connection_pool.with_connection {
      ::Mdm::WmapRequest.where("wmap_requests.host = ? AND wmap_requests.port = ? #{extra_condition}", host , port)
    }
  end

  #
  # WMAP
  # This methods returns a list of all targets in the database
  #
  def requests
    ::ActiveRecord::Base.connection_pool.with_connection {
      ::Mdm::WmapRequest.find(:all)
    }
  end
end