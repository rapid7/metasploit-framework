# -*- coding: binary -*-

module Rex
module Post
module HWBridge
module Extensions
module Automotive

module UDSErrors

# Negative Response Codes (NDC)
ERR_MNEMONIC = {
  0x10 => "GR",
  0x11 => "SNS",
  0x12 => "SFNS",
  0x13 => "IMLOIF",
  0x14 => "RTL",
  0x21 => "BRR",
  0x22 => "CNC",
  0x24 => "RSE",
  0x25 => "NRFSC",
  0x26 => "FPEORA",
  0x31 => "ROOR",
  0x33 => "SAD",
  0x35 => "IK",
  0x36 => "ENOA",
  0x37 => "RTDNE",
  0x38 => "RBEDLSD",
  0x39 => "RBEDLSD",
  0x3A => "RBEDLSD",
  0x3B => "RBEDLSD",
  0x3C => "RBEDLSD",
  0x3D => "RBEDLSD",
  0x3E => "RBEDLSD",
  0x3F => "RBEDLSD",
  0x40 => "RBEDLSD",
  0x41 => "RBEDLSD",
  0x42 => "RBEDLSD",
  0x43 => "RBEDLSD",
  0x44 => "RBEDLSD",
  0x45 => "RBEDLSD",
  0x46 => "RBEDLSD",
  0x47 => "RBEDLSD",
  0x48 => "RBEDLSD",
  0x49 => "RBEDLSD",
  0x4A => "RBEDLSD",
  0x4B => "RBEDLSD",
  0x4C => "RBEDLSD",
  0x4D => "RBEDLSD",
  0x4E => "RBEDLSD",
  0x4F => "RBEDLSD",
  0x70 => "UDNA",
  0x71 => "TDS",
  0x72 => "GPF",
  0x73 => "WBSC",
  0x78 => "RCRRP",
  0x7E => "SFNSIAS",
  0x7F => "SNSIAS",
  0x81 => "RPMTH",
  0x82 => "RPMTL",
  0x83 => "EIR",
  0x84 => "EINR",
  0x85 => "ERTTL",
  0x86 => "TTH",
  0x87 => "TTL",
  0x88 => "VSTH",
  0x89 => "VSTL",
  0x8A => "TPTH",
  0x8B => "TPTL",
  0x8C => "TRNIN",
  0x8D => "TRNIG",
  0x8F => "BSNC",
  0x90 => "SLNIP",
  0x91 => "TCCL",
  0x92 => "VTH",
  0x93 => "VTL"
}

ERR_DESC = {
  "GR" => "General Reject",
  "SNS" => "Service Not Supported",
  "SFNS" => "Sub-Function Not Supported",
  "IMLOIF" => "Incorrect Message Length Or Invalid Format",
  "RTL" => "Response Too Long",
  "BRR" => "Busy Repeat Request",
  "CNC" => "Conditions Not Correct",
  "RSE" => "Request Sequence Error",
  "NRFSC" => "No Response From Sub-net Component",
  "FPEORA" => "Failure Prevents Execution Of Requested Action",
  "ROOR" => "Request Out Of Range",
  "SAD" => "Security Access Denied",
  "IK" => "Invalid Key",
  "ENOA" => "Exceeded Number Of Attempts",
  "RTDNE" => "Required Time Delay Not Expired",
  "RBEDLSD" => "Reserved By Extended Data Link Security Document",
  "UDNA" => "Upload/Download Not Accepted",
  "TDS" => "Transfer Data Suspended",
  "GPF" => "General Programming Failure",
  "WBSC" => "Wrong Block Sequence Counter",
  "RCRRP" => "Request Correctly Received, but Response is Pending",
  "SFNSIAS" => "Sub-Function Not Supoorted In Active Session",
  "SNSIAS" => "Service Not Supported In Active Session",
  "RPMTH" => "RPM Too High",
  "RPMTL" => "RPM Too Low",
  "EIR" => "Engine is Running",
  "EINR" => "Engine is not Running",
  "ERTTL" => "Engine Run Time Too Low",
  "TTH" => "Temperature Too High",
  "TTL" => "Temperature Too Low",
  "VSTH" => "Vehicle Speed Too High",
  "VSTL" => "Vehicle Speed Too Low",
  "TPTH" => "Throttle Pedal Too High",
  "TPTL" => "Throttle Pedal Too Low",
  "TRNIN" => "Transmission Range Not in Neutral",
  "TRNIG" => "Transmission Range Not in Gear",
  "BSNC" => "Brake Switch Not Closed",
  "SLNIP" => "Shifter Lever Not In Park",
  "TCCL" => "Torque Converter Clutch Locked",
  "VTH" => "Voltage Too High",
  "VTL" => "Voltage Too Low"
}

end

end
end
end
end
end
