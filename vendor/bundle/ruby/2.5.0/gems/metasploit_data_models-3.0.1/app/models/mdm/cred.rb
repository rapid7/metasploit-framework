# @deprecated Use metasploit-credential's `Metasploit::Credential::Core`.
#
# A credential captured from a {#service}.
class Mdm::Cred < ActiveRecord::Base
  #
  # CONSTANTS
  #

  # Checks if {#proof} is an SSH Key in {#ssh_key_id}.
  KEY_ID_REGEX = /([0-9a-fA-F:]{47})/

  # Maps {#ptype_human} to {#ptype}.
  PTYPES = {
      'read/write password' => 'password_rw',
      'read-only password' => 'password_ro',
      'SMB hash' => 'smb_hash',
      'SSH private key' => 'ssh_key',
      'SSH public key' => 'ssh_pubkey'
  }

  #
  #
  # Associations
  #
  #

  # The {Mdm::Service} this Cred is for.
  belongs_to :service,
             class_name: 'Mdm::Service',
             inverse_of: :creds

  # Joins {#tasks} to this Cred.
  has_many :task_creds,
           class_name: 'Mdm::TaskCred',
           dependent: :destroy,
           inverse_of: :cred

  #
  # through: :task_creds
  #

  # Tasks that touched this service
  has_many :tasks, :through => :task_creds

  #
  # Attributes
  #

  # @!attribute active
  #   Whether the credential is active.
  #
  #   @return [false] if a captured credential cannot be used to log into {#service}.
  #   @return [true] otherwise

  # @!attribute created_at
  #   When this credential was created.
  #
  #   @return [DateTime]

  # @!attribute pass
  #   Pass of credential.
  #
  #   @return [String, nil]

  # @!attribute proof
  #   Proof of credential capture.
  #
  #   @return [String]

  # @!attribute ptype
  #   Type of {#pass}.
  #
  #   @return [String]

  # @!attribute source_id
  #   Id of source of this credential.
  #
  #   @return [Integer, nil]

  # @!attribute source_type
  #   Type of source with {#source_id}.
  #
  #   @return [String, nil]

  # @!attribute updated_at
  #   The last time this credential was updated.
  #
  #   @return [DateTime]

  # @!attribute user
  #   User name of credential.
  #
  #   @return [String, nil]

  #
  # Callbacks
  #

  after_create :increment_host_counter_cache
  after_destroy :decrement_host_counter_cache

  #
  # Instance methods
  #

  # Humanized {#ptype}.
  #
  # @return [String, nil]
  def ptype_human
    humanized = PTYPES.select do |k, v|
      v == ptype
    end.keys[0]

    humanized ? humanized : ptype
  end

  # Returns SSH Key ID.
  #
  # @return [String] SSH Key Id if ssh-type key and {#proof} matches {KEY_ID_REGEX}.
  # @return [nil] otherwise
  def ssh_key_id
    return nil unless self.ptype =~ /^ssh_/
    return nil unless self.proof =~ KEY_ID_REGEX
    $1.downcase # Can't run into NilClass problems.
  end

  # Returns whether `other`'s SSH private key or public key matches.
  #
  # @return [false] if `other` is not same class as `self`.
  # @return [false] if {#ptype} does not match.
  # @return [false] if {#ptype} is neither `"ssh_key"` nor `"ssh_pubkey"`.
  # @return [false] if {#ssh_key_id} is `nil`.
  # @return [false] if {#ssh_key_id} does not match.
  # @return [true] if {#ssh_key_id} matches.
  def ssh_key_matches?(other_cred)
    return false unless other_cred.kind_of? self.class
    return false unless self.ptype == other_cred.ptype
    case self.ptype
      when "ssh_key"
        matches = self.ssh_private_keys
      when "ssh_pubkey"
        matches = self.ssh_public_keys
      else
        return false
    end
    matches.include?(self) and matches.include?(other_cred)
  end

  # Returns all keys with matching key ids, including itself.
  #
  # @return [ActiveRecord::Relation<Mdm::Cred>] ssh_key and ssh_pubkey creds with matching {#ssh_key_id}.
  def ssh_keys
    (self.ssh_private_keys | self.ssh_public_keys)
  end

  # Returns all private keys with matching {#ssh_key_id}, including itself.
  #
  # @return [ActiveRecord::Relation<Mdm::Cred>] ssh_key creds with matching {#ssh_key_id}.
  def ssh_private_keys
    return [] unless self.ssh_key_id
    matches = Mdm::Cred.where(
        "ptype = ? AND proof ILIKE ?", "ssh_key", "%#{self.ssh_key_id}%"
    ).to_a
    matches.select {|c| c.workspace == self.workspace}
  end

  # Returns all public keys with matching {#ssh_key_id}, including itself.
  #
  # @return [ActiveRecord::Relation<Mdm::Cred>] ssh_pubkey creds with matching {#ssh_key_id}.
  def ssh_public_keys
    return [] unless self.ssh_key_id
    matches = Mdm::Cred.where(
        "ptype = ? AND proof ILIKE ?", "ssh_pubkey", "%#{self.ssh_key_id}%"
    ).to_a
    matches.select {|c| c.workspace == self.workspace}
  end

  # Returns its workspace
  #
  # @return [Mdm::Workspace]
  def workspace
    self.service.host.workspace
  end

  private

  # Decrements {Mdm::Host#cred_count}.
  #
  # @return [void]
  def decrement_host_counter_cache
    Mdm::Host.decrement_counter("cred_count", self.service.host_id)
  end

  # Increments {Mdm::Host#cred_count}.
  #
  # @return [void]
  def increment_host_counter_cache
    Mdm::Host.increment_counter("cred_count", self.service.host_id)
  end

  # Switch back to public for load hooks.
  public

  Metasploit::Concern.run(self)
end
