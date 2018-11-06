# Tag {#hosts_tags assigned} to {#hosts}.  Tags can be used to group together hosts for targeting and reporting.
class Mdm::Tag < ActiveRecord::Base
  include Metasploit::Model::Search

  #
  # Associations
  #

  # Joins {#hosts} to this tag.
  has_many :hosts_tags,
           class_name: 'Mdm::HostTag',
           dependent: :destroy,
           inverse_of: :tag

  # User that created this tag.
  belongs_to :user,
             class_name: 'Mdm::User',
             inverse_of: :tags

  #
  # through: :hosts_tags
  #

  # Hosts that are tagged with this tag.
  has_many :hosts, :through => :hosts_tags, :class_name => 'Mdm::Host'

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this tag was created by {#user}.
  #
  #   @return [DateTime]

  # @!attribute critical
  #   Whether this tag represents a critical finding about the {#hosts}.
  #
  #   @return [true] this tag is critical.
  #   @return [false] this tag is non-critical.

  # @!attribute desc
  #   Longer description of what this tag should be used for or means when applied to a {#hosts host}.
  #
  #   @return [String]

  # @!attribute name
  #   The name of the tag.  The name is what a user actually enters to tag a {#hosts host}.
  #
  #   @return [String]

  # @!attribute report_detail
  #   Whether to include this tag in a report details section.
  #
  #   @return [true] include this tag in the report details section.
  #   @return [false] do not include this tag in the report details section.

  # @!attribute report_summary
  #   Whether to include this tag in a report summary section.
  #
  #   @return [true] include this tag in the report summary section.
  #   @return [false] do not include this tag in the report summary section.

  # @!attribute updated_at
  #   The last time this tag was updated.
  #
  #   @return [DateTime]

  #
  # Search
  #

  search_attribute :desc,
                   type: :string
  search_attribute :name,
                   type: :string

  #
  # Validations
  #

  validates :desc,
            :length => {
                :maximum => ((8 * (2 ** 10)) - 1),
                :message => I18n.t('activerecord.ancestors.mdm/tag.model.errors.messages.length')
            }
  validates :name,
            :format => {
                :with => /\A[A-Za-z0-9\x2e\x2d_]+\z/, :message => I18n.t('activerecord.ancestors.mdm/tag.model.errors.messages.character')
            },
            :presence => true

  #
  # Instance Methods
  #

  # Destroy this tag if it has no {#hosts_tags}
  #
  # @return [void]
  def destroy_if_orphaned
    self.class.transaction do
      if hosts_tags.empty?
        destroy
      end
    end
  end

  # (see #name)
  def to_s
    name
  end

  Metasploit::Concern.run(self)
end
