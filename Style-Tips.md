# Style Tips

## Editor configuration

Having your editor take care of formatting for you can save headaches during the acceptance process. Most Metasploit contributors use vim and/or gvim as a default text editor -- if you have a configuration for some other editor, we'd love to see it!

### VIM and GVIM

Adding the following settings to your .vimrc will make conforming to the [HACKING](https://github.com/rapid7/metasploit-framework/blob/master/HACKING) and [msftidy.rb](https://github.com/rapid7/metasploit-framework/blob/master/tools/msftidy.rb) guidelines considerably easier.

    set shiftwidth=2 tabstop=2 softtabstop=2
    " textwidth affects `gq` which is handy for formatting comments
    set textwidth=78
    " Metasploit requires spaces instead of hard tabs
    set expandtab
    " Highlight spaces at EOL and mixed tabs and spaces.
    hi BogusWhitespace ctermbg=darkgreen guibg=darkgreen
    " Note that this regex matches spaces at the beggining of lines which can
    " get annoying when editing other kinds of files that use spaces for tabs.
    " If you want this match to apply only to ruby files, see the augroup
    " implementation below.
    match BogusWhitespace /\s\+$\|^\t\+ \+\|^ \+\t*/


If you'd rather these settings only apply to ruby files, you can use an autogroup and autocommands.

    if !exists("au_loaded")
        let au_loaded = 1
        augroup rb
            au FileType ruby set shiftwidth=4 tabstop=4 softtabstop=4 textwidth=78
            au FileType ruby set noexpandtab
            au FileType ruby hi BogusWhitespace ctermbg=darkgreen guibg=darkgreen
            au FileType ruby match BogusWhitespace /\s\+$\|^\t\+ \+\|^ \+\t*/
        augroup END
    endif

You can also use `:set list` to see all whitespace as distinct characters to make it easier to see errant whitespace.

### Rubymine

Go to Preferences in the Rubymine window menu.  In the 'Project Settings [metasploit-framework]' section go to Code Style > Ruby.  Change the Scheme dropdown from Default to Project.  Then in the Project section under the Tabs and Indents tab, check 'Use tab character' and 'Smart tabs'.  Set the 'Tab size' and 'Indent' to 4 and the 'Continuation indent' to 8 as it should be twice the normal indent.  All other Code Style options can follow the defaults.

## Grammar and capitalization

While we understand that the world reads many, many languages, Metasploit is developed primarily in U.S English. Therefore, description grammar in modules should adhere to U.S. English conventions. Doing so not only ensures ease of use for the majority of Metasploit users, but also helps automatic (and manual) translators for other languages.

### Titles

Module titles should read like titles. For capitalization rules in English, see: http://owl.english.purdue.edu/owl/resource/592/01/
    
The only exceptions are function names (like 'thisFunc()') and specific filenames (like thisfile.ocx). Module titles should be contrived so both the first and last word begins with a capital letter, as this is an [msftidy.rb](https://github.com/rapid7/metasploit-framework/blob/master/tools/msftidy.rb) check.
