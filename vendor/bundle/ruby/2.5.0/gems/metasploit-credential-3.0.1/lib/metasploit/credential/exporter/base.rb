# Defines attributes common to allow exporters.
module Metasploit::Credential::Exporter::Base
  extend ActiveSupport::Concern

  included do
    include ActiveModel::Validations

    # @!attribute data
    #   A {Hash} that holds the credentials data to be exported.
    #   @return [Hash]
    attr_accessor :data

    # @!attribute output
    #   An {IO} that holds the exported data. {File} in normal usage.
    #   @return [IO]
    attr_accessor :output

    # @!attribute workspace
    #   The {Mdm::Workspace} that the credentials will be exported from
    #   @return[Mdm::Workspace]
    attr_accessor :workspace
  end

  #
  # Instance Methods
  #

  # @param attributes [Hash{Symbol => String,nil}]
  def initialize(attributes={})
    attributes.each do |attribute, value|
      public_send("#{attribute}=", value)
    end
  end
end
