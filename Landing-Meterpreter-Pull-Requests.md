[[Landing Pull Requests]] is only part of getting a new Meterpreter change out in the wild. There are multiple repositories that that need to be aligned in order to get the Meterpreter source code up-to-date, the meterpreter_bins gem rebuilt, and finally adding a dependency on metasploit-framework on the new Meterpreter binaries.

Luckily, these steps are sequential, so there are no dependencies that will get you into trouble if you follow the correct order.

 - Land the PR at https://github.com/rapid7/meterpreter first,
     test first by copying the DLLs, .so, etc. into metasploit-framework/data/meterpreter
 - Update the meterpreter_gems repository, bump the version
 - Get @cdoughty-r7 to push the build button to build and publish a new version of the meterpreter_gems gem
 - ..to be continued..