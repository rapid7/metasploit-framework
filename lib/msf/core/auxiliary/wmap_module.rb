# -*- coding: binary -*-
module Msf
###
#
# This module provides methods for WMAP-enabled modules
#
###

module Auxiliary::WmapModule

  attr_accessor :orderid
  attr_accessor :requiredids

  #
  # Initializes an instance of a WMAP module
  #
  def initialize(info = {})
    super
    self.orderid = 0xFFFFFF
    self.requiredids = {}
  end

  def register_wmap_options(options)
    if options.has_key?('OrderID')
      self.orderid = options['OrderID']
    end

    if 	options.has_key?('Require')
      self.requiredids = options['Require']
    end
  end

  def wmap_enabled
    #enabled by default
    true
  end

  def wmap_getoid
    self.orderid
  end

  def wmap_setoid(oid)
    self.orderid = oid
  end

  def wmap_type
    #default type
    nil
  end

  def wmap_target_host
    datastore['RHOST']
  end

  def wmap_target_port
    datastore['RPORT']
  end

  def wmap_target_ssl
    datastore['SSL']
  end

  def wmap_target_vhost
    datastore['VHOST']
  end

  def wmap_base_url
    res = (ssl ? "https://" : "http://")
    if datastore['VHOST'].nil?
      res << wmap_target_host
    else
      res << datastore['VHOST']
    end
    res << ":" + wmap_target_port.to_s
    res
  end


  #
  # Modified from CGI.rb as we dont use arrays
  #
  def headersparse(qheaders)
    params = Hash.new()

    qheaders.split(/[&;]/n).each do |pairs|
      key, value = pairs.split(':',2)
      if params.has_key?(key)
        #Error
      else
        params[key] = value
      end
    end
    params
  end

  #modified from CGI.rb as we dont use arrays
  def queryparse(query)
    params = Hash.new()

    query.split(/[&;]/n).each do |pairs|
      key, value = pairs.split('=',2)
      if params.has_key?(key)
        #Error
      else
        params[key] = value
      end
    end
    params
  end

  # Levenshtein distance algorithm  (slow, huge mem consuption)
  def distance(a, b)
    case
    when a.empty?
      b.length
    when b.empty?
      a.length
    else
      [(a[0] == b[0] ? 0 : 1) + distance(a[1..-1], b[1..-1]),
      1 + distance(a[1..-1], b),
      2 + distance(a, b[1..-1])].min
    end
  end

end

end
