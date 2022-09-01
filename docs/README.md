# Metasploit docs site

This folder maintains the docs for https://docs.metasploit.com/ and https://github.com/rapid7/metasploit-framework/wiki

## Architecture

How it works:

- `build.rb` - The main entry point for generating the docs site from the old Github Wiki format files within `metasploit-framework.wiki/`
- `navigation.rb` - Stores the mapping of `metasploit-framework.wiki` files to the website's navigational structure
- `metasploit-framework.wiki/` - The raw markdown documentation files. Modify these files when updating the site. These files originally came from https://github.com/rapid7/metasploit-framework/wiki 
- `metasploit-framework.wiki.old/` - A separate clone of https://github.com/rapid7/metasploit-framework/wiki

Behind the scenes these docs are built and deployed to https://docs.metasploit.com/

## Setup

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


### Contributing Documentation

You can modify existing documentation files within `metasploit-framework.wiki/` with an editor of your choice and send a pull request.
Note that adding a new page will also require modifying `navigation.rb` to appear on the navigation menu.
