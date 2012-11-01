class Mdm::Tag < ActiveRecord::Base
  #
  # Callbacks
  #

  before_destroy :cleanup_hosts

  #
  # Relations
  #

  has_many :hosts_tags, :class_name => 'Mdm::HostTag'
  belongs_to :user, :class_name => 'Mdm::User'

  #
  # Through :hosts_tags
  #
  has_many :hosts, :through => :hosts_tags, :class_name => 'Mdm::Host'


  #
  # Validations
  #

  validates :desc,
            :length => {
                :maximum => ((8 * (2 ** 10)) - 1),
                :message => "desc must be less than 8k."
            }
  validates :name,
            :format => {
                :with => /^[A-Za-z0-9\x2e\x2d_]+$/, :message => "must be alphanumeric, dots, dashes, or underscores"
            },
            :presence => true

  def cleanup_hosts
    # Clean up association table records
    Mdm::HostTag.delete_all("tag_id = #{self.id}")
  end

  def to_s
    name
  end

  ActiveSupport.run_load_hooks(:mdm_tag, self)
end
