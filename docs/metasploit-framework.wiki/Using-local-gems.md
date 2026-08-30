## Introduction
Often times when testing Gem file updates, particularly from other repositories such as [rex-powershell](https://github.com/rapid7/rex-powershell) or [rex-text](https://github.com/rapid7/rex-text), one will need to find some way of testing whether the updated Gem file works as expected within Metasploit Framework. There are many different ways to do this, however this guide will only focus on one method for simplicities sake, as this is the one that has been known to work with the least amount of prerequisite setup.

## Instructions
1. Set up a working Metasploit development setup as described at the [[Setting Up a Development Environment|./dev/Setting-Up-a-Metasploit-Development-Environment.md]] wiki page. Be sure to set up your SSH keys as part of this setup.
2. Clone whatever PR it is that you wish to work on. For example to work on <https://github.com/rapid7/rex-text/pull/30>, do `git clone git@github.com:rapid7/rex-text.git`, then `cd rex-text`, followed by `git checkout origin/pr/30`.
3. Go to the location of your git clone of Metasploit Framework and do `cp Gemfile.local.example Gemfile.local`. Ensure that no file named `Gemfile.local.lock` exists. If one does, remove it.
4. Inside your `Gemfile.local` file, edit it so it looks something like the following:

```ruby
##
# Example Gemfile.local file for Metasploit Framework
#
# The Gemfile.local file provides a way to use other gems that are not
# included in the standard Gemfile provided with Metasploit.
# This filename is included in Metasploit's .gitignore file, so local changes
# to this file will not accidentally show up in future pull requests. This
# example Gemfile.local includes all gems in Gemfile using instance_eval.
# It also creates a new bundle group, 'local', to hold additional gems.
#
# This file will not be used by default within the framework. As such, one
# must first install the custom Gemfile.local with bundle:
#   bundle install --gemfile Gemfile.local
#
# Note that msfupdate does not consider Gemfile.local when updating the
# framework. If it is used, it may be necessary to run the above bundle
# command after the update.
#
###

# Include the Gemfile included with the framework. This is very
# important for picking up new gem dependencies.
msf_gemfile = File.join(File.dirname(__FILE__), 'Gemfile')
if File.readable?(msf_gemfile)
  instance_eval(File.read(msf_gemfile))
end

# Create a custom group
group :local do
   gem 'rex-powershell', path: '/home/gwillcox/git/rex-powershell'
end
```

Notice in particular the final part of this code:

```ruby
# Create a custom group
group :local do
   gem 'rex-powershell', path: '/home/gwillcox/git/rex-powershell'
end
```

For each gem you want to test, you will need both the name of the gem, for example `rex-powershell` or `rex-text`, followed by `path:` and the path where the corresponding Git repository for that gem is on disk. Do this for each custom gem that you want to test out, then save and close `Gemfile.local`.

5. Whilst still inside the cloned Metasploit Framework git repository, execute `bundle install --gemfile Gemfile.local`. You should see a line similar to the following:

```
Using rex-powershell 0.1.87 from source at `/home/gwillcox/git/rex-powershell`
```

6. If any errors occur, follow the directions in the output to try and resolve the conflicts. If all else fails, delete `Gemfile.local.lock` and run `bundle install --gemfile Gemfile.local` again.
