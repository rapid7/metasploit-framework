# Style Tips

## Editor configuration

Having your editor take care of formatting for you can save headaches during the acceptance process. Most Metasploit contributors use vim and/or gvim as a default text editor -- if you have a configuration for some other editor, we'd love to see it!

### VIM and GVIM

Adding the following settings to your .vimrc will make conforming to the [CONTRIBUTING.md](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md) and [msftidy.rb](https://github.com/rapid7/metasploit-framework/blob/master/tools/dev/msftidy.rb) guidelines considerably easier. 

Incidentally, if you install the [Janus Distribution](https://github.com/carlhuda/janus) of vim plugins, this is all done for you, and more, automatically. But, if you are a special snowflake, here's how to limp your way to code formatting excellence.

```
set shiftwidth=2 tabstop=2 softtabstop=2
" textwidth affects `gq` which is handy for formatting comments
set textwidth=78
" Metasploit requires spaces instead of hard tabs
set expandtab
" Highlight spaces at EOL and mixed tabs and spaces.
hi BogusWhitespace ctermbg=darkgreen guibg=darkgreen
match BogusWhitespace /\s\+$\|^\t\+ \+\|^ \+\t\+/
```

If you'd rather these settings only apply to ruby files, you can use an autogroup and autocommands.

```
if !exists("au_loaded")
    let au_loaded = 1
    augroup rb
        au FileType ruby set shiftwidth=2 tabstop=2 softtabstop=2 textwidth=78
        au FileType ruby set expandtab
        au FileType ruby hi BogusWhitespace ctermbg=darkgreen guibg=darkgreen
        au FileType ruby match BogusWhitespace /\s\+$\|^\t\+ \+\|^ \+\t\+/
    augroup END
endif
```

You can also use `:set list` to see all whitespace as distinct characters to make it easier to see errant whitespace.

### Rubymine

Given the switch to using standard Ruby indentation, there is no special configuration needed for RubyMine any longer. Two-space tabs for life!

## Grammar and capitalization

While we understand that the world reads many, many languages, Metasploit is developed primarily in U.S English. Therefore, description grammar in modules should adhere to U.S. English conventions. Doing so not only ensures ease of use for the majority of Metasploit users, but also helps automatic (and manual) translators for other languages.

### Titles

Module titles should read like titles. For capitalization rules in English, see: http://owl.english.purdue.edu/owl/resource/592/01/
    
The only exceptions are function names (like `thisFunc()`) and specific filenames (like `thisfile.ocx`).