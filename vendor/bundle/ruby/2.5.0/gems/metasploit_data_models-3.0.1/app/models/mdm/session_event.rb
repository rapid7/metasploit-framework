# Events that occurred when using a {#session}.
class Mdm::SessionEvent < ActiveRecord::Base
  
  #
  # Associations
  #

  # The session in which the event occurred.
  belongs_to :session,
             class_name: 'Mdm::Session',
             inverse_of: :events

  # @!attribute command
  #   The command that was run through the session that triggered this event.
  #
  #   @return [String]

  # @!attribute created_at
  #   When this event occurred.
  #
  #   @return [DateTime]

  # @!attribute etype
  #   The type of the event.
  #
  #   @return [String]

  # @!attribute local_path
  #   The current local directory when {#command} was run.
  #
  #   @return [String]

  # @!attribute output
  #   The {#output} of running {#command}.
  #
  #   @return [String]

  # @!attribute remote_path
  #   The current remote directory when {#command} was run.
  #
  #   @return [String]

  Metasploit::Concern.run(self)
end
