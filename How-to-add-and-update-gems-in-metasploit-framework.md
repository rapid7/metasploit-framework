Sometimes you might want to pull in a new Ruby library or update an existing one to get more functionality. Here's how to do it.

Metasploit leverages [Ruby gems](https://rubygems.org/) to make dependencies easy. Gems that are only *sometimes* used (say, only in test mode, or only when running with a database) are listed in the [root Gemfile](https://github.com/rapid7/metasploit-framework/blob/master/Gemfile). Gems that are *always needed* by Metasploit are kept in the [metasploit-framework.gemspec](https://github.com/rapid7/metasploit-framework/blob/master/metasploit-framework.gemspec) file (this file is actually pulled into the Gemfile).

##### The Lock File

The [Gemfile.lock file](https://github.com/rapid7/metasploit-framework/blob/master/Gemfile.lock) holds the absolute versions of the Gems we want and keeps track of all the subdependencies. You should never need to manually edit this file. We keep this committed in the repo to ensure that all users are always on the same gem versions.

##### Updating or adding a gem

1. Edit the [metasploit-framework.gemspec](https://github.com/rapid7/metasploit-framework/blob/master/metasploit-framework.gemspec) file. You should add the gem as a runtime dependency, or just update the version constraint. Check [Bundler's docs](http://bundler.io/gemfile.html) for the various ways to express version constraints:

        spec.add_runtime_dependency 'my_favorite_gem', '~> 3.0.1'

2. Run `bundle install`
3. Commit any changes to the `Gemfile.lock` file.

##### Gemfile.local

A Gemfile.local file is useful for adding temporary gems to the metasploit-framework, like pry-stack-explorer or other handy debugging libs; you don't want to commit these gems into the repo, but might need them from time to time. To use a Gemfile.local file:

1. Rename the [Gemfile.local.example](https://github.com/rapid7/metasploit-framework/blob/master/Gemfile.local.example) file in the repo root to `Gemfile.local`
2. Add the temporary gems you want to this file
3. Run `bundle install`
4. Make sure you _do not_ commit the Gemfile.lock: `git checkout -- Gemfile.lock`