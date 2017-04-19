# Automated pieces for the Weekly Metasploit Wrapup blog posts

1. Clone https://github.com/egypt/metasploit-stats 
1. Run `get_release_notes.rb <start tag> <end tag>`
   * this will create a file called `release_notes_<tag>_<tag>.html` (e.g. `release_notes_4.13.20_4.13.25.html`)
1. Open `release_notes.html` in a browser and figure out what's important for the wrapup.
1. Run [`msf-wrapup.rb`](https://github.com/egypt/metasploit-stats/blob/master/msf-wrapup.rb) in the `metasploit-framework` checkout:
   * `../metasploit-stats/msf-wrapup.rb <start tag> <end tag>  >> weekly.md`
1. Edit: `vim weekly.md`
1. When you're done, convert to html: `pandoc -f markdown -t html weekly.md`
