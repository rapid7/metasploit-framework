#!/usr/bin/python3
import requests
import re

def replace_agent_string(lines, replace_marker, url, regex):
  VALID_CHARS = 'a-zA-Z0-9\\(\\);:\\.,/_ '
  regex = regex.replace('{VALID_CHARS}', VALID_CHARS)
  print(f'Updating {replace_marker}')
  for x in range(0, len(lines)):
    if replace_marker in lines[x]:
      break
  else:
    raise RuntimeError(f"Couldn't find marker {replace_marker}")

  response = requests.get(url)
  if response.status_code != 200:
    raise RuntimeError(f"Can't retrieve {url}")

  match = re.search(regex, response.text)
  if match is None:
    raise RuntimeError(f"Couldn't match regex {regex}")

  new_string = match.groups()[0]
  print(f'New value is: {new_string}')
  old_line = lines[x]
  if f"'{new_string}'" in old_line:
    print('(This is unchanged from the previous value)')
  else:
    new_line = re.sub("'(.*)'", f"'{new_string}'", old_line)
    if old_line == new_line:
      raise RuntimeError(f"Line didn't change: {old_line}")

    lines[x] = new_line


chrome_url = "https://www.whatismybrowser.com/guides/the-latest-user-agent/chrome"
edge_url = "https://www.whatismybrowser.com/guides/the-latest-user-agent/edge"
safari_url = "https://www.whatismybrowser.com/guides/the-latest-user-agent/safari"
firefox_url = "https://www.whatismybrowser.com/guides/the-latest-user-agent/firefox"

user_agent_filename = 'lib/rex/user_agent.rb'
with open(user_agent_filename,'r') as f:
  lines = f.read().splitlines()

replace_agent_string(lines, 'Chrome Windows', chrome_url, '<td>Chrome \\(Standard\\)</td>\\s*<td>\\s*<ul>\\s*<li><span class="code">([{VALID_CHARS}]*Windows NT[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Chrome MacOS', chrome_url, '<td>Chrome \\(Standard\\)</td>\\s*<td>\\s*<ul>\\s*<li><span class="code">([{VALID_CHARS}]*Macintosh[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Edge Windows', edge_url, '<td>Edge \\(Standard\\)</td>\\s*<td>\\s*<ul>\\s*<li><span class="code">([{VALID_CHARS}]*Windows NT[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Safari iPad', safari_url, '<td>\\s*Safari on <b>Ipad</b>\\s*</td>\\s*<td>\\s*<ul>\\s*<li><span class="code">([{VALID_CHARS}]*iPad[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Safari MacOS', safari_url, '<td>Safari \\(Standard\\)</td>\\s*<td>\\s*<ul>\\s*<li><span class="code">([{VALID_CHARS}]*Macintosh[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Firefox Windows', firefox_url, '<td>\\s*Firefox on <b>Windows</b>\\s*</td>\\s*<td>\\s*<ul>\\s*<li><span class="code">([{VALID_CHARS}]*Windows NT[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Firefox MacOS', firefox_url, '<td>\\s*Firefox on <b>Macos</b>\\s*</td>\\s*<td>\\s*<ul>\\s*<li><span class="code">([{VALID_CHARS}]*Macintosh[{VALID_CHARS}]*)</span>')

with open(user_agent_filename, 'w') as f:
  f.write('\n'.join(lines) + '\n')

print('Done')
