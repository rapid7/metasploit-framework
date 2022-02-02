module Msf::DBManager::Adapter
  #
  # CONSTANTS
  #

  # The adapter to use to establish database connection.
  ADAPTER = 'postgresql'

  #
  # Attributes
  #

  # Returns the list of usable database drivers
  def drivers
    @drivers ||= []
  end
  attr_writer :drivers

  # Returns the active driver
  attr_accessor :driver

  #
  # Instance Methods
  #

  #
  # Scan through available drivers
  #
  def initialize_adapter
    ApplicationRecord.default_timezone = :utc

    if connection_established? && ApplicationRecord.connection_db_config.configuration_hash[:adapter] == ADAPTER
      dlog("Already established connection to #{ADAPTER}, so reusing active connection.")
      self.drivers << ADAPTER
      self.driver = ADAPTER
    else
      begin
        ApplicationRecord.establish_connection(adapter: ADAPTER)
        ApplicationRecord.remove_connection
      rescue Exception => error
        @adapter_error = error
      else
        self.drivers << ADAPTER
        self.driver = ADAPTER
      end
    end
  end
end
