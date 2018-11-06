## v1.6.5 (2016-07-08)
* Removed Faker::ChuckNorris.name

## v1.6.4 (2016-07-06)
* Removed support for Ruby 1.9.3
* Added Faker::ChuckNorris, Faker::Crypto, Faker::Educator, Faker::File, Faker::Music, Faker::Space, Faker::Vehicle, and Faker::Yoda
* Fixed bug with credit card types
* DST fixes in Faker::Time
* Added Faker::Name.name_with_middle
* Added Faker::Code.imei
* Added Faker::Code.asin
* Added Faker::Lorem.question and Faker::Lorem.questions
* Added Faker::Internet.private_ip_v4_address
* Added Faker::Company.australian_business_number
* Other miscellaneous fixes and locale updates

## v1.6.3 (2016-02-23)
* Fix for UTF problem in Ruby 1.9.3
* Fix for Faker::StarWars.character
* Updated sv locale

## v1.6.2 (2016-02-20)
* Fix for locale-switching (Russian email addresses)
* Added Faker::Beer, Faker::Boolean, Faker::Cat, Faker::StarWars, and Faker::Superhero
* Added Faker::Color.color_name
* Added Faker::Date.between_except
* Fixed Faker::Internet.ip_v4_cidr and Faker::Internet.ip_v6_cidr
* Added locales: ca, ca-CAT, da-DK, fi-FI, and pt

## v1.6.1 (2015-11-23)
* Fix for locale issues in tests

## v1.6.0 (2015-11-23)
* Lots of bug fixes -- most notably, a fix for email addresses and domains in non-en locales
* Updated locales: de, en-AU, en-NZ, en-SG, en-US, en-au-ocker, en, es, fr, he, it, ja, nb-NO, pl, pt-BR, sk, and zh-CN
* Updated classes: Address, Avatar, Book, Code, Commerce, Company, Hipster, IDNumber, Internet, Number, Placeholdit, Shakespeare, and Time 

## v1.5.0 (2015-08-17)
* Added logos
* Added Slack Emoji
* Updated image generators
* Updated Dutch Locale
* Added support for generating RGB values, HSL colors, alpha channel, and HSLA colors
* Added locale for Uganda
* Added basic Ukrainian support
* Added university name generator
* Updated documentation
* Updated a variety of locales
* Various fixes

## v1.4.3 (2014-08-15)
* Updated Russian locale
* Added EIN generator
* Fixed Swedish locale
* Added birthday to Faker::Date
* Added Faker::App

## v1.4.2 (2014-07-15)
* Added Swedish locale
* README update

## v1.4.1 (2014-07-04)
* Bugfix and cleanup

## v1.4.0 (2014-07-03)
* Many enhancements and bugfixes

## v1.3.0 (2014-03-08)
* Many enhancements and few bugfixes

## v1.2.0 (2013-07-27)
* Many major and minor enhancements :)

## v1.1.2 (2012-09-18)
* 1 minor change:
    * Fixed Ruby 1.8 compatibility

## v1.1.1 (2012-09-17)
* 1 minor change:
    * Removed ja locale because of parse errors

## v1.1.0 (2012-09-15)
* 1 major change:
    * Removed deprecated methods from Address: earth_country, us_state, us_state_abbr, uk_postcode, uk_county
* Many minor changes (please see github pull requests for credits)
    * Added many localizations 
    * Added range and array support for Lorem

## v1.0.1 (2011-09-27)
* 1 minor enhancement
    * Added safe_email method to get someaddress@example.com [Kazimierz Kiełkowicz]
* 1 bug fix:
    * Use the locale fallback properly when parsing string formats

## v1.0.0 (2011-09-08)
* 2 major enhancements
    * Moved all formats to locale files
    * Stopped interfering with I18n's global settings for fallbacks
* 3 minor bug fixes:
    * Ruby 1.9.2 fixes [eMxyzptlk]
    * UTF8 fixes [maxmiliano]
    * Updated IPv4 generator to return valid addresses [Sylvain Desbureaux]
* Many minor enhancements:
    * Added bork locale for bork-ified lorem [johnbentcope]
    * Added IPv6 address generator [jc00ke]
    * Removed deprecation warnings for Array#rand [chrismarshall]
    * Added German translation and I18n improvments [Matthias Kühnert]
    * Added Dutch translation [moretea]
    * Added Lat/Long generator [Andy Callaghan]
    * Added buzzword-laden title generator [supercleanse]
    * Added optional extended wordlist for lorem [chriskottom]
    * Updated German translation [Jan Schwenzien]
    * Locale improvements [suweller]
    * Added limit to lorem generator [darrenterhune]
    * Added Brazilian Portuguese translation [maxmiliano]
    * Added Australian translation [madeindata]
    * Added Canadian translation [igbanam]
    * Added Norwegian translation [kytrinyx]
    * Lots of translation-related cleanup [kytrinyx]
  

## v0.9.5 (2011-01-27)
* 1 minor bug fix:
    * Fixed YAML [Aaron Patterson]
* 3 minor enhancements:
    * Added default rake task to run all tests [Aaron Patterson]
    * Removed shuffle method [Aaron Patterson]
    * Use psych if present [Aaron Patterson]

## v0.9.4 (2010-12-29)
* 1 minor bug fix:
    * Stopped getting in the way of Rails' late locale loading

## v0.9.3 (2010-12-28)
* 1 minor enhancement:
    * Added a faker namespace for translations

## v0.9.2 (2010-12-22)
* 1 bug fix:
    * Stopped stomping on I18n load path

## v0.9.1 (2010-12-22)
* 1 bug fix:
    * Stopped setting I18n default locale
* 1 major enhancement:
    * Added method_missing to Address to add methods based on data in locale files
* 1 minor enhancement:
    * Added Swiss locale [Lukas Westermann]

## v0.9.0 (2010-12-21)
* 1 major enhancement:
    * Moved strings and some formats to locale files

## v0.3.1 (2008-04-03)
* 1 minor enhancement:
    * Added city to Address

## v0.3.0 (2008-01-01)
* 3 major enhancements:
    * Added Lorem to generate fake Latin
    * Added secondary_address to Address, and made inclusion of
    secondary address in street_address optional (false by 
    default).
    * Added UK address methods [Caius Durling]

## v0.2.1 (2007-12-05)
* 1 major enhancement:
    * Dropped facets to avoid conflict with ActiveSupport
* 2 minor enhancements:
    * Changed the output of user_name to randomly separate with a . or _
    * Added a few tests

## v0.1.0 (2007-11-22)

* 1 major enhancement:
    * Initial release
