# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::StatusCodes
  SUCCESS = 0
  CONNECTION_FAILED = 1
  UNEXPECTED_REPLY = 2
  NO_ACCESS = 3
  NO_DOMAINS = 4
  NO_BUILD_NUMBER = 5

  # Alias for Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::StatusCodes
  # @return [Module] Returns the Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::StatusCodes module reference.
  def adaudit_plus_status
    Msf::Exploit::Remote::HTTP::ManageEngineAdauditPlus::StatusCodes
  end
end
