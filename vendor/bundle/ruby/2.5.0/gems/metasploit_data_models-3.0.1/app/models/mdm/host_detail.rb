# Details supplied by Nexpose about a {Mdm::Host host}.
class Mdm::HostDetail < ActiveRecord::Base
  #
  # Associations
  #

  # Host that this detail is about.
  belongs_to :host,
             class_name: 'Mdm::Host',
             counter_cache: :host_detail_count,
             inverse_of: :host_details

  #
  # Attributes
  #

  # @!attribute host_id
  #   The foreign key used to look up {#host}.
  #
  #   @return [Integer]

  # @!attribute nx_console_id
  #   The ID of the Nexpose console.
  #
  #   @return [Integer]

  # @!attribute nx_device_id
  #   The ID of the Device in Nexpose.
  #
  #   @return [Integer]

  # @!attribute nx_risk_score
  #   Risk score assigned by Nexpose.  Useful to ordering hosts to determine which host to target first in metasploit.
  #
  #   @return [Float]

  # @!attribute nx_scan_template
  #   The template used by Nexpose to perform the scan on the {#nx_site_name site} on {#host}.
  #
  #   @return [String]

  # @!attribute nx_site_importance
  #   The importance of scanning the {#nx_site_name site} running on {#host} according to Nexpose.
  #
  #   @return [String]

  # @!attribute nx_site_name
  #   Name of site running on {#host} according to Nexpose.
  #
  #   @return [String]

  # @!attribute src
  #    @return [String]

  #
  # Validations
  #

  validates :host_id, :presence => true

  Metasploit::Concern.run(self)
end