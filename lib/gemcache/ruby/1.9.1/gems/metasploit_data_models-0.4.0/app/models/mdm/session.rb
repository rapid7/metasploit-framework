class Mdm::Session < ActiveRecord::Base
  #
  # Callbacks
  #

  before_destroy :stop

  #
  # Relations
  #

  has_many :events, :class_name => 'Mdm::SessionEvent', :order => 'created_at', :dependent => :delete_all
  belongs_to :host, :class_name => 'Mdm::Host'
  has_many :routes, :class_name => 'Mdm::Route', :dependent => :delete_all

  #
  # Through :host
  #
  has_one :workspace, :through => :host, :class_name => 'Mdm::Workspace'

  #
  # Scopes
  #

  scope :alive, where('closed_at IS NULL')
  scope :dead, where('closed_at IS NOT NULL')
  scope :upgradeable, where("closed_at IS NULL AND stype = 'shell' and platform ILIKE '%win%'")

  #
  # Serializations
  #

  serialize :datastore, ::MetasploitDataModels::Base64Serializer.new

  def upgradeable?
    (self.platform =~ /win/ and self.stype == 'shell')
  end

  private

  def stop
    c = Pro::Client.get rescue nil
    # ignore exceptions (XXX - ideally, stopped an already-stopped session wouldn't throw XMLRPCException)
    c.session_stop(self.local_id) rescue nil
  end

  ActiveSupport.run_load_hooks(:mdm_session, self)
end
