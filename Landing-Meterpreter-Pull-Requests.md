[[Landing Pull Requests]] is only part of getting a new Meterpreter change out in the wild. There are multiple repositories that that need to be aligned in order to get the Meterpreter source code up-to-date, the meterpreter_bins gem rebuilt, and finally adding a dependency on metasploit-framework on the new Meterpreter binaries.

Luckily, these steps are sequential, so there are no dependencies that will get you into trouble if you follow the correct order.

 - Land the PR at https://github.com/rapid7/meterpreter first.
     Test by copying the DLLs, .so, etc. into metasploit-framework/data/meterpreter.
 - Update the https://github.com/rapid7/meterpreter_bins repository and bump the version.
     Maybe it is already bumped compared to the latest published version?
     Check https://rubygems.org/gems/meterpreter_bins and compare.
     In your PR to bump the version number, it is nice to refer to what issue #'s or PR's
     the next version will have. Maybe we should tag meterpreter with the gem version #'s?
 - Get @cdoughty-r7 to push the build button to build and publish a new version of the gem.
 - Wait for it to publish and become downloadable.
 - Update metasploit-framework.gemspec to the new gem version.
 - Make sure the new meterpreter_bins gets downloaded and updated with msfupdate / bundle install.
 - Submit or land PR with the new functionality + the gemspec update in https://github.com/rapid7/metasploit-framework