[[Landing Pull Requests]] is only part of getting a new Meterpreter change out in the wild. There are multiple repositories that that need to be aligned in order to get the Meterpreter source code up-to-date, the meterpreter_bins gem rebuilt, and finally adding a dependency on metasploit-framework on the new Meterpreter binaries.

Luckily, these steps are sequential, so there are no dependencies that will get you into trouble if you follow the correct order.

 - Land the PR at https://github.com/rapid7/meterpreter first.
     Test by copying the DLLs, .so, etc. into metasploit-framework/data/meterpreter.
 - Push the build buttons in jenkins to generate and publish a new version of the gem. @cdoughty-r7 and @bcook-r7 can push said buttons, which also increment the version number in the meterpreter_bins project as a side-effect.
 - Wait for it to publish and become downloadable. This takes no time at all.
 - Update metasploit-framework.gemspec to the new gem version. Install that gem.
 - Make sure the new meterpreter_bins gets downloaded and updated with msfupdate / bundle install.
 - Test the thing again.
 - Submit or land PR with the new functionality + the gemspec update in https://github.com/rapid7/metasploit-framework