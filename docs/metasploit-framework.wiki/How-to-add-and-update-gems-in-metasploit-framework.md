**Update:** We have automated this process (it runs every Thursday at noon US Central Time), and 99.9% of the time you will not need to follow any of the below steps. That said, if you need to update a gem in a PR, this is still a good procedure to follow.

Sometimes you might want to pull in a new Ruby library or update an existing one to get more functionality. Metasploit leverages [Bundler](http://bundler.io) to manage [Ruby gems](https://rubygems.org/) and make dependencies easy. This document goes over the things you need to know when updating or adding gems to Metasploit.

##### The Gemfile

Gems that are only *sometimes* used (say, only in test mode, or only when running with a database) are listed in a relevant Bundler group (`test` or `db` respectively) in the [root Gemfile](https://github.com/rapid7/metasploit-framework/blob/master/Gemfile).

##### The metasploit-framework.gemspec file

Gems that are *always needed* by Metasploit are kept in the [metasploit-framework.gemspec](https://github.com/rapid7/metasploit-framework/blob/master/metasploit-framework.gemspec) file (this file is actually pulled into the Gemfile when calculating dependencies).

##### The Lock File

The [Gemfile.lock file](https://github.com/rapid7/metasploit-framework/blob/master/Gemfile.lock) holds the absolute versions of the Gems we want and keeps track of all the subdependencies. You should never need to manually edit this file: bundler will do it for you when you run `bundle install` after adding a gem. We keep this committed in the repo to ensure that all users are always on the same gem versions.

##### Updating or adding a gem

If the gem is needed only for a specific Bundler group (like `test` or `db`), you should update the [Gemfile](https://github.com/rapid7/metasploit-framework/blob/master/Gemfile):

1. Add the Gem you want to the correct Group, or just update the version constraint. Check [Bundler's docs](http://bundler.io/gemfile.html) for the various ways to express version constraints:

        gem 'my_favorite', '~> 1.0'

2. Run `bundle install`
3. Commit any changes to the `Gemfile.lock` file

If the gem is needed any time metasploit-framework is used, you should update the [metasploit-framework.gemspec](https://github.com/rapid7/metasploit-framework/blob/master/metasploit-framework.gemspec) file:

1. Add the gem as a runtime dependency, or just update the version constraint. Check [Bundler's docs](http://bundler.io/gemfile.html) for the various ways to express version constraints:

        spec.add_runtime_dependency 'my_favorite_gem', '~> 3.0.1'

2. Run `bundle install`
3. Commit any changes to the `Gemfile.lock` file.

##### Gemfile.local

A Gemfile.local file is useful for adding temporary gems to the metasploit-framework, like pry-stack-explorer or other handy debugging libs; you don't want to commit these gems into the repo, but might need them from time to time. To use a Gemfile.local file:

1. Rename the [Gemfile.local.example](https://github.com/rapid7/metasploit-framework/blob/master/Gemfile.local.example) file in the repo root to `Gemfile.local`
2. Add the temporary gems you want to this file
3. Run `bundle install`
4. Make sure you _do not_ commit the Gemfile.lock: `git checkout -- Gemfile.lock`