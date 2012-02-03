# Style Tips

Having your editor take care of formatting for you can save headaches during the acceptance process.

## VIM

Adding the following settings to your .vimrc will make conforming to the [HACKING](https://github.com/rapid7/metasploit-framework/blob/master/HACKING) and [msftidy.rb](https://github.com/rapid7/metasploit-framework/blob/master/tools/msftidy.rb) guidelines considerably easier.

    set shiftwidth=4 tabstop=4 softtabstop=4
    " textwidth affects `gq` which is handy for formatting comments
    set textwidth=78
    " Metasploit generally requires hard tabs instead of spaces
    set noexpandtab
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



