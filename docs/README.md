# Metasploit docs site

## Setup 

### Build content

First build the latest docs content from the existing [Metasploit Wiki](https://github.com/rapid7/metasploit-framework/wiki). This a temporary
solution until the docs content is directly committed to the [metasploit-framework](https://github.com/rapid7/metasploit-framework) repository. 

```
bundle install
bundle exec ruby build.rb
```

### Running

Running:

```
bundle install
bundle exec jekyll serve --config _config.yml,_config_development.yml --incremental
```

Now visit http://127.0.0.1:4000

### Production build

Testing production build:
```
rm -rf _site
bundle install
bundle exec ruby build.rb
JEKYLL_ENV=production jekyll build
```

### Modifying pages

**Note** - to modify pages, for now, the changes will need to be made to [Metasploit Wiki](https://github.com/rapid7/metasploit-framework/wiki).
However the `docs` folder can be edited locally. Jekyll will rebuild the required file, and the changes can be seen after refreshing your browser.

When adding test files locally, Jekyll will not always regenerate the navigation for all pages. It is easier to regenerate the entire site again:

```
rm -rf _site
bundle exec jekyll serve --config _config.yml,_config_development.yml --incremental
```
