require 'msf/core/module/reference'

###
#
# A reference to a website.
#
###
class Msf::Module::SiteReference < Msf::Module::Reference
  # Converts the `ary` to a {Msf::Module::SiteReference}.
  #
  # @param ary [Array<(String, String)>] Array of {#ctx_id} and {#ctx_val}.
  # @return [Msf::Module::SiteReference] if `ary` has two elements,
  # @return [nil] if `ary` does not have two elements.
  def self.from_a(ary)
    if ary.length == 2
      self.new(*ary)
    else
      nil
    end
  end

  # Converts URL `str` to a {Msf::Module::SiteReference}.
  #
  # @return [Msf::Module::SiteReference] if {#from_s} returns `true`.
  # @return [nil] if {#from_s} returns `false`.
  def self.from_s(str)
    instance = self.new

    if instance.from_s(str)
      instance
    else
      nil
    end
  end

  # @param in_ctx_id [String] Context for `in_ctx_val`.  Either `'URL'` or a
  #   `Metasploit::Model::Authority#abbreviation`.
  # @param in_ctx_val [String] Value scoped to `in_ctx_id`.  Either a url if `in_ctx_id` is `'URL'` or a
  #   `Metasploit::Model::Reference#designation`.
  def initialize(in_ctx_id = 'Unknown', in_ctx_val = '')
    self.ctx_id  = in_ctx_id
    self.ctx_val = in_ctx_val
  end

  # The absolute site URL.
  #
  # @return [String] {#site}
  # @return [''] if {#site} is `nil`
  def to_s
    return site || ''
  end

  #
  # Serializes a site URL string.
  #
  def from_s(str)
    updated = false

    if (/(http:\/\/|https:\/\/|ftp:\/\/)/.match(str))
      self.site = str
      self.ctx_id  = 'URL'
      self.ctx_val = self.site

      updated = true
    end

    updated
  end

  # The site being referenced.
  #
  # @see Metasploit::Model::Reference#url
  def site
    unless instance_variable_defined? :@site
      if extension
        @site = extension.designation_url(ctx_val)
      elsif ctx_id == 'URL'
        @site = ctx_val.to_s
      else
        site_parts = [ctx_id]

        if ctx_val.present?
          site_parts << "(#{ctx_val})"
        end

        @site = site_parts.join(' ')
      end
    end

    @site
  end

  #
  # The context identifier of the site, such as OSVDB.
  #
  attr_reader :ctx_id
  #
  # The context value of the reference, such as MS02-039
  #
  attr_reader :ctx_val

protected

  attr_writer :site, :ctx_id, :ctx_val

  private

  # Returns module that includes authority specific methods.
  #
  # @return [Module] if {#ctx_id} has a corresponding module under the Metasploit::Model::Authority namespace.
  # @return [nil] otherwise.
  def extension
    begin
      extension_name.constantize
    rescue NameError
      nil
    end
  end

  # Returns the name of the module that includes authority specific methods.
  #
  # @return [String] unless {#ctx_id} is blank.
  # @return [nil] if {#abbreviation} is blank.
  def extension_name
    extension_name = nil

    unless ctx_id.blank?
      # underscore before camelize to eliminate -'s
      relative_model_name = ctx_id.underscore.camelize
      # don't scope to self.class.name so that authority extension are always resolved the same in Mdm and
      # Metasploit::Framework.
      extension_name = "Metasploit::Model::Authority::#{relative_model_name}"
    end

    extension_name
  end

end