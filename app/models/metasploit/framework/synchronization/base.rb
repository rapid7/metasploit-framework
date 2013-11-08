# Base class for classes that sync the cache to metadata in metasploit.
class Metasploit::Framework::Synchronization::Base < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] destination
  #   The destination to be synchronized with {#source}.
  #
  #   @return [ActiveRecord::Base]
  attr_accessor :destination

  # @!attribute [rw] source
  #   The source of information to synchronize to {#destination}.
  #
  #   @return [Object]
  attr_accessor :source

  #
  # Validations
  #

  validates :destination,
            presence: true
  validates :source,
            presence: true

  #
  # Methods
  #

  # Synchronizes {#destination} to {#source} by adding and removing associated records from
  # {#destination}.
  def self.synchronize(&block)
    define_method(:synchronize) do
      ActiveRecord::Base.connection_pool.with_connection do
        # transaction so that bulk removes and adds are performed together
        ActiveRecord::Base.transaction do
          instance_eval(&block)
        end
      end
    end
  end

  private

  def added_attributes_set
    @added_attributes_set ||= source_attributes_set - destination_attributes_set
  end

  def removed_attributes_set
    @removed_attributes_set ||= destination_attributes_set - source_attributes_set
  end
end