# Building the Docs Locally
Whilst you can always browse the documentation at https://docs.metasploit.com/, sometimes there are cases where you may not be able to reach this site, such as when you are on a client engagement with limited or no access to the public internet.

In these cases, you may want to build the documentation site locally so that you can still access and search the documentation offline. This guide will explain how to do that.

## Overview
All documentation located at https://docs.metasploit.com/ is also available locally under the `docs/` folder, located at the root of wherever you have cloned/installed Metasploit.

## Architecture
How it works:

- `build.rb` - The main entry point for generating the docs site from the old Github Wiki format files within `metasploit-framework.wiki/`
- `navigation.rb` - Stores the mapping of `metasploit-framework.wiki` files to the website's navigational structure
- `metasploit-framework.wiki/` - The raw markdown documentation files. Modify these files when updating the site. These files originally came from https://github.com/rapid7/metasploit-framework/wiki 
- `metasploit-framework.wiki.old/` - A separate clone of https://github.com/rapid7/metasploit-framework/wiki

Behind the scenes these docs are built and deployed to https://docs.metasploit.com/

## Building Documentation

### Developer build

Builds the latest docs content from the existing [Metasploit Wiki](https://github.com/rapid7/metasploit-framework/wiki), and
serves the files locally:

```bash
cd metasploit-framework/docs

bundle install
bundle exec ruby build.rb --serve
```

Now visit http://127.0.0.1:4000

### Production build

Builds the latest docs content from the existing [Metasploit Wiki](https://github.com/rapid7/metasploit-framework/wiki), creates
a production Jekyll build, and serves the files locally:

```bash
cd metasploit-framework/docs

bundle install
bundle exec ruby build.rb --production --serve
```

Now visit http://127.0.0.1:4000/metasploit-framework/

## Contributing Documentation
You can modify existing documentation files within `metasploit-framework.wiki/` with an editor of your choice and send a pull request.
Note that adding a new page will also require modifying `navigation.rb` so that the page appears on the navigation menu.
