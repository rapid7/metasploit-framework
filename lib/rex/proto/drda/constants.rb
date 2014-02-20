# -*- coding: binary -*-
require 'rex/proto/drda'

module Rex
module Proto
module DRDA
class Constants

require 'rex/text'

# DRDA Code Points

EXCSAT     = 0x1041 # Exchange Server Attributes
EXTNAM     = 0x115e # External Name
MGRLVLLS   = 0x1404 # Manager-Level List
SRVCLSNM   = 0x1147 # Server Class Name
SRVNAM     = 0x116d # Server Name
SRVRLSLV   = 0x115a # Server Product Release Level
ACCSEC     = 0x106d # Access Security
SECMEC     = 0x11a2 # Security Mechanism
RDBNAM     = 0x2110 # Relational Database Name
SECTKN     = 0x11dc # Security Token
EXCSATRD   = 0x1443 # Server Attributes Reply Data
ACCSECRD   = 0x14ac # Access Security Reply Data
SRVDGN     = 0x1153 # Server Diagnostic Information
RDBNFNRM   = 0x2211 # Relational Database Not Found
SECCHK     = 0x106e # Security Check
USERID     = 0x11a0 # Remote User ID
PASSWORD   = 0x11a1 # Remote Password
RDBACCCL   = 0x210f # RDB Access Manager Class
PRDID      = 0x112e # Product-Specific Identifier
PRDDTA     = 0x2104 # Product-Specific Data
TYPEDEFNAM = 0x002f # Data Type Definition Name
TTPEDEFOVR = 0x0035 # TYPEDEF Overrides
CRRTKN     = 0x2135 # Correlation Token
TRGDFTRT   = 0x213b # Target Default Value Return
SQLCARD    = 0x2408 # SQL Communications Area Reply Data
SECCHKRM   = 0x1219 # Security Check Response Message
SRVCOD     = 0x1149 # Severity Code
SECCHKCD   = 0x11a4 # Security Check Code
ACCRDBRM   = 0x2201 # Access to RDB Completed

def self.const_values
  self.constants.map {|x| self.const_get x}
end

end
end
end
end
