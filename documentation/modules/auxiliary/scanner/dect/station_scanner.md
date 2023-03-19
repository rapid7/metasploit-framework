## Vulnerable Application

DECT stands for Digital Enhanced Cordless Telecommunications. The wireless standard is often used for landline phones. A DECT system always contains two components that constantly communicate with each other. The two components are a base station, also called the fixed part, and at least one handset, or portable part. This module scans for DECT Stations and outputs data regarding the time of the call, RFPI data, and channel data.  

## Verification Steps

  1. Start msfconsole
  2. Do: `use auxiliary/scanner/dect/station_scanner`
  3. Do: `run`

## Options

Call scanner currently has no options.

## Scenarios