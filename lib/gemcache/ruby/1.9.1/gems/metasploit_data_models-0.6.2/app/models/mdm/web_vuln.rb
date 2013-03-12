# A Web Vulnerability found during a web scan or web audit.
#
# If you need to modify Mdm::WebVuln you can use ActiveSupport.on_load(:mdm_web_vuln) inside an initializer so that
# your patches are reloaded on each request in development mode for your Rails application.
#
# @example extending Mdm::WebVuln
#   # config/initializers/mdm_web_vuln.rb
#   ActiveSupport.on_load(:mdm_web_vuln) do
#     def confidence_percentage
#       "#{confidence}%"
#     end
#   end
class Mdm::WebVuln < ActiveRecord::Base
  #
  # CONSTANTS
  #

  # A percentage {#confidence} that the vulnerability is real and not a false positive.
  CONFIDENCE_RANGE = 0 .. 100

  # Default value for {#params}
  DEFAULT_PARAMS = []

  # Allowed {#method methods}.
  METHODS = [
      'GET',
      # XXX I don't know why PATH is a valid method when it's not an HTTP Method/Verb
      'PATH',
      'POST'
  ]

  # {#risk Risk} is rated on a scale from 0 (least risky) to 5 (most risky).
  RISK_RANGE = 0 .. 5

  #
  # Associations
  #

  belongs_to :web_site, :class_name => 'Mdm::WebSite'

  #
  # Attributes
  #

  # @!attribute [rw] blame
  #   Who to blame for the vulnerability
  #
  #   @return [String]

  # @!attribute [rw] category
  #   Category of this vulnerability.
  #
  #   @return [String]

  # @!attribute [rw] confidence
  #   Percentage confidence scanner or auditor has that this vulnerability is not a false positive
  #
  #   @return [Integer] 1% to 100%

  # @!attribute [rw] description
  #   Description of the vulnerability
  #
  #   @return [String, nil]

  # @!attribute [rw] method
  #   HTTP Methods for request that found vulnerability.  'PATH' is also allowed even though it is not an HTTP Method.
  #
  #   @return [String]
  #   @see METHODS

  # @!attribute [rw] name
  #   Name of the vulnerability
  #
  #   @return [String]

  # @!attribute [rw] path
  #   Path portion of URL
  #
  #   @return [String]

  # @!attribute [rw] payload
  #   Web audit payload that gets executed by the remote server.  Used for code injection vulnerabilities.
  #
  #   @return [String, nil]

  # @!attribute [rw] pname
  #   Name of parameter that demonstrates vulnerability
  #
  #   @return [String]

  # @!attribute [rw] proof
  #   String that proves vulnerability, such as a code snippet, etc.
  #
  #   @return [String]

  # @!attribute [rw] query
  #   The GET query.
  #
  #   @return [String]

  # @!attribute [rw] request
  #
  #   @return [String]

  # @!attribute [rw] risk
  #   {RISK_RANGE Risk} of leaving this vulnerability unpatched.
  #
  #   @return [Integer]

  #
  # Validations
  #

  validates :category, :presence => true
  validates :confidence,
            :inclusion => {
                :in => CONFIDENCE_RANGE
            }
  validates :method,
            :inclusion => {
                :in => METHODS
            }
  validates :name, :presence => true
  validates :path, :presence => true
  validates :pname, :presence => true
  validates :proof, :presence => true
  validates :risk,
            :inclusion => {
                :in => RISK_RANGE
            }
  validates :web_site, :presence => true

  #
  # Serializations
  #

  # @!attribute [rw] params
  #   Parameters sent as part of request
  #
  #   @return [Array<Array<(String, String)>>] Array of parameter key value pairs
  serialize :params, MetasploitDataModels::Base64Serializer.new(:default => DEFAULT_PARAMS)

  #
  # Methods
  #

  # Parameters sent as part of request.
  #
  # @return [Array<Array<(String, String)>>]
  def params
    normalize_params(
        read_attribute(:params)
    )
  end

  # Set parameters sent as part of request.
  #
  # @param params [Array<Array<(String, String)>>, nil] Array of parameter key value pairs
  # @return [void]
  def params=(params)
    write_attribute(
        :params,
        normalize_params(params)
    )
  end

  private

  # Creates a duplicate of {DEFAULT_PARAMS} that is safe to modify.
  #
  # @return [Array] an empty array
  def default_params
    DEFAULT_PARAMS.dup
  end

  # Returns either the given params or {DEFAULT_PARAMS} if params is `nil`
  #
  # @param [Array<Array<(String, String)>>, nil] params
  # @return [Array<<Array<(String, String)>>] params if not `nil`
  # @return [nil] if params is `nil`
  def normalize_params(params)
    params || default_params
  end

  # switch back to public for load hooks
  public

  ActiveSupport.run_load_hooks(:mdm_web_vuln, self)
end

