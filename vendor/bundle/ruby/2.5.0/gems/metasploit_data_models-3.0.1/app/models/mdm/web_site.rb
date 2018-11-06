# A Web Site running on a {#service}.
class Mdm::WebSite < ActiveRecord::Base
  
  #
  # Associations
  #

  # The service on which this web site is running.
  belongs_to :service,
             class_name: 'Mdm::Service',
             foreign_key: 'service_id',
             inverse_of: :web_sites

  # Filled-in forms within this web site.
  has_many :web_forms,
           class_name: 'Mdm::WebForm',
           dependent: :destroy,
           inverse_of: :web_site

  # Web pages found on this web site.
  has_many :web_pages,
           class_name: 'Mdm::WebPage',
           dependent: :destroy,
           inverse_of: :web_site

  # Vulnerabilities found on this web site.
  has_many :web_vulns,
           class_name: 'Mdm::WebVuln',
           dependent: :destroy,
           inverse_of: :web_site

  #
  # Attributes
  #

  # @!attribute [rw] comments
  #   User entered comments about this web site.
  #
  #   @return [String]

  # @!attribute [rw] created_at
  #   When this web site was created.
  #
  #   @return [DateTime]

  # @!attribute [rw] updated_at
  #   The last time this web site was updated.
  #
  #   @return [DateTime]

  # @!attribute [rw] vhost
  #   The virtual host for the web site in case `service.host.name` or `service.host.address` is no the host for this
  #   web site.
  #
  #   @return [String]

  #
  # Serializations
  #

  # @!attribute [rw] options
  #   @todo Determine format and purpose of Mdm::WebSite#options.
  serialize :options, ::MetasploitDataModels::Base64Serializer.new

  #
  # Instance Methods
  #

  # Number of {#web_forms}.
  #
  # @return [Integer]
  def form_count
    web_forms.size
  end

  # Number of {#web_pages}.
  #
  # @return [Integer]
  def page_count
    web_pages.size
  end

  # Converts this web site to its URL, including scheme, host and port.
  #
  # @param ignore_vhost [Boolean] if `false` use {#vhost} for host portion of URL.  If `true` use {Mdm::Host#address} of
  #   {Mdm::Service#host} of {#service} for host portion of URL.
  # @return [String] <scheme>://<host>[:<port>]
  def to_url(ignore_vhost=false)
    proto = self.service.name == "https" ? "https" : "http"
    host = ignore_vhost ? self.service.host.address.to_s : self.vhost
    port = self.service.port

    if Rex::Socket.is_ipv6?(host)
      host = "[#{host}]"
    end

    url = "#{proto}://#{host}"
    if not ((proto == "http" and port == 80) or (proto == "https" and port == 443))
      url += ":#{port}"
    end
    url
  end

  # Number of {#web_vulns}.
  #
  # @return [Integer]
  def vuln_count
    web_vulns.size
  end

  Metasploit::Concern.run(self)
end

