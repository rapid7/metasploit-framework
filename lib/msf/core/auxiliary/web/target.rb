# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/

require 'net/https'
require 'net/http'
require 'uri'

module Msf

#
# Represents a targeted web application and holds service, host, post etc. info.
#
class Auxiliary::Web::Target

  # Original URL as a String.
  attr_accessor :original

  # Service information as an Mdm::Service object.
  attr_accessor :service

  # Mdm::WebSite object.
  attr_accessor :site

  # True if HTTPS, False otherwise.
  attr_accessor :ssl

  # IP address as a String.
  attr_accessor :host

  # Virtual host as a String.
  attr_accessor :vhost

  # String URI path.
  attr_accessor :path

  # String URI query.
  attr_accessor :query

  # Port Number.
  attr_accessor :port

  # Port Number.
  attr_accessor :username

  # Port Number.
  attr_accessor :password

  # Array of Web::Form objects.
  attr_accessor   :forms

  # Array of Web::Path objects.
  attr_accessor   :paths

  #
  # options - Hash with which to populate self (keys must correspond to attributes):
  #           :service
  #           :ssl
  #           :host
  #           :vhost
  #           :path
  #           :port
  #           :forms
  #           :auditable
  #
  def initialize( options = {} )
    update( options )
  end

  #
  # options - Hash with which to update self (keys must correspond to attributes):
  #           :service
  #           :ssl
  #           :host
  #           :vhost
  #           :path
  #           :port
  #           :forms
  #           :auditable
  #
  def update( options = {} )
    options.each { |k, v| send( "#{k}=", v ) }

    @forms ||= []
    @paths ||= []

    self
  end

  #
  # Pushes an auditable element.
  #
  # element - Web::Form or Web::Path or Mdm::WebForm
  #
  def <<( element )

    case element
      when Auxiliary::Web::Path
        @paths << element
      when Auxiliary::Web::Form
        @forms << element
      when Mdm::WebForm
        self.<< element.method.to_s.downcase == 'path' ?
          Auxiliary::Web::Path.from_model( element ) :
                  Auxiliary::Web::Form.from_model( element )
    end
  end

  #
  # Array of accumulated auditable elements.
  #
  def auditable
    self.forms | self.paths
  end

  def host
    return if !@host
    Rex::Socket.is_ipv6?( @host ) ? "[#{@host}]" : @host
  end

  # String protocol representation (http or https).
  def proto
    ssl? ? 'https' : 'http'
  end

  # True if HTTPS, False otherwise.
  def ssl?
    !!@ssl
  end

  # String URL to the webapp.
  def to_url
    "#{proto}://#{vhost || host}:#{port}#{path}"
  end

  def dup
    Marshal.load( Marshal.dump( self ) )
  end

end
end
