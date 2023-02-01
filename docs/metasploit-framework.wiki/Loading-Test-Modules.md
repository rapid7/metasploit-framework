By default test modules in Metasploit are not loaded when Metasploit starts. To load them, run `loadpath test/modules` after which you should see output similar to the following:

```msf
msf6 > loadpath test/modules
Loaded 38 modules:
    14 auxiliary modules
    13 exploit modules
    11 post modules
msf6 > 
```

These modules are intended to be used by developers to test updates to ensure they don't break core functionality and should not be used during normal operations. If you do happen to break the functionality of one of these modules, it is highly recommended that you look at what you are proposing within your PR and ensure that you are not accidentally breaking unintended functionality. If you do need to break certain functionality in order to add a given feature, and there is no other way to go around this, be sure to let one of the Metasploit team members know this so that appropriate updates can be made to these scripts and any associated code that may be updated by your change (assuming it is has been signed off and approved by the team).
