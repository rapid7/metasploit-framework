# Metasploit docs site

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

### Modifying pages

**Note** - to modify pages, for now, the changes will need to be made to [Metasploit Wiki](https://github.com/rapid7/metasploit-framework/wiki).
However the `docs` folder can be edited locally. Jekyll will rebuild the required file, and the changes can be seen after refreshing your browser.

When adding test files locally, Jekyll will not always regenerate the navigation for all pages. It is easier to rebuild the entire site again.
