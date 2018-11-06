# Search operation on an attribute that holds a port number and is being searched with a single Integer port number.
class MetasploitDataModels::Search::Operation::Port::Number < Metasploit::Model::Search::Operation::Integer
  #
  # CONSTANTS
  #

  # The number of bits in a port number
  BITS = 16
  # The maximum port number
  MAXIMUM = (1 << BITS) - 1
  # The minimum port number
  MINIMUM = 0

  # The range of valid port numbers from {MINIMUM} to {MAXIMUM}, inclusive.
  RANGE = (MINIMUM..MAXIMUM)

  #
  # Validations
  #

  validates :value,
            inclusion: {
                in: RANGE
            }
end