#!/usr/bin/python3
import requests

new_com = requests.get("https://raw.githubusercontent.com/rezasp/joomscan/master/exploit/db/componentslist.txt").text
with open('data/wordlists/joomla.txt', 'r') as j:
    old = j.read().splitlines()

for com in new_com.splitlines():
    if not 'components/%s/'%(com) in old:
        old.append('components/%s/'%(com))
        print('[+] Adding: components/%s/'%(com))

old.sort()
with open('data/wordlists/joomla.txt', 'w') as j:
    j.write('\n'.join(old))
    j.write('\n')
