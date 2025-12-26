module Rex::Proto::MsTds
  class MsTdsType < BinData::Uint8
    SQL_BATCH                   = 1  # (Client) SQL command
    PRE_TDS7_LOGIN              = 2  # (Client) Pre-login with version < 7 (unused)
    RPC                         = 3  # (Client) RPC
    TABLE_RESPONSE              = 4  # (Server)  Pre-Login Response ,Login Response, Row Data, Return Status, Return Parameters,
    # Request Completion, Error and Info Messages, Attention Acknowledgement
    ATTENTION_SIGNAL            = 6  # (Client) Attention
    BULK_LOAD                   = 7  # (Client) SQL Command with binary data
    TRANSACTION_MANAGER_REQUEST = 14 # (Client) Transaction request manager
    TDS7_LOGIN                  = 16 # (Client) Login
    SSPI_MESSAGE                = 17 # (Client) Login
    PRE_LOGIN_MESSAGE           = 18 # (Client) pre-login with version > 7

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def to_sym
      self.class.name(value)
    end
  end
end
