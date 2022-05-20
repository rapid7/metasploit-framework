When the Metasploit Payloads has a new merge appear in `master`, a new Ruby gem is built and automatically pushed up to [RubyGems](https://rubygems.org/gems/metasploit-payloads/). This new version needs to be merged into the Metasploit Framework repository for those changes to be included.

To do this, committers must:

* Create a new branch in the Metasploit Framework repository.
* Name it something useful like `metasploit-payloads-<version>`.
* Modify `metasploit-framework.gemspec`, so that the new version number is specified for the `metasploit-payloads` gem.
* Run `bundle install`.
* Remove any test/development binaries from `data/meterpreter`.
* Run `tools/modules/update_payload_cached_sizes.rb`.
* Make sure that `Gemfile.lock` only contains changes that are related to Metasploit Payloads.
* Stage the following for commit in `git`:
    * `Gemfile.lock`
    * `metasploit-framework.gemspec`
    * Any payload modules that have had an updated payload size (usually this includes stageless payloads only)
* Commit the staged files.
* Push the branch to github.
* Create the Pull Request.

Done!

A sample update PR/commit can be found here: <https://github.com/rapid7/metasploit-framework/pull/7666/files>
