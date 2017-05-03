class Mdm::Loot < ActiveRecord::Base
  #
  # Callbacks
  #

  before_destroy :delete_file

  #
  # CONSTANTS
  #

  RELATIVE_SEARCH_FIELDS = [
      'ltype',
      'name',
      'info',
      'data'
  ]

  #
  # Relations
  #

  belongs_to :host, :class_name => 'Mdm::Host'
  belongs_to :service, :class_name => 'Mdm::Service'
  belongs_to :workspace, :class_name => 'Mdm::Workspace'

  #
  # Scopes
  #

  scope :search, lambda { |*args|
    # @todo replace with AREL
    terms = RELATIVE_SEARCH_FIELDS.collect { |relative_field|
      "loots.#{relative_field} ILIKE ?"
    }
    disjunction = terms.join(' OR ')
    formatted_parameter = "%#{args[0]}%"
    parameters = [formatted_parameter] * RELATIVE_SEARCH_FIELDS.length
    conditions = [disjunction] + parameters

    where(conditions)
  }

  #
  # Serializations
  #

  serialize :data, MetasploitDataModels::Base64Serializer.new

  private

  def delete_file
    c = Pro::Client.get rescue nil
    if c
      c.loot_delete_file(self[:id])
    else
      ::File.unlink(self.path) rescue nil
    end
  end

  ActiveSupport.run_load_hooks(:mdm_loot, self)
end

