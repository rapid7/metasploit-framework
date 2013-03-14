## 2.0.2 (03 April 2012)

  - Updated to jQuery 1.7.2
  - Updated to jQuery UI 1.8.18
  - Updated to latest jquery-ujs
    - Override provided for obtaining `href`
    - Edit `crossDomain` and `dataType` from `ajax:before` event

## 2.0.1 (28 February 2012)

  - Fixed Rails 3.2 dependency issue

## 2.0 (20 December 2011)

  - Minimum dependency set to Rails 3.2

## 1.0.19 (26 November 2011)

  - Updated to jQuery 1.7.1
  - Updated to latest jquery-ujs
    - Fixed disabled links to re-enable when `ajax:before` or
      `ajax:beforeSend` are canceled
    - Switched from deprecated `live` to `delegate`

## 1.0.18 (18 November 2011)

  - Updated to latest jquery-ujs
    - Fixed event parameter for form submit event handlers in IE for
      jQuery 1.6.x
    - Fixed form submit event handlers for jQuery 1.7

## 1.0.17 (9 November 2011)

  - Updated to jQuery 1.7
  - Updated to latest jquery-ujs
    - Moved file comment above function so it won't be included in
      compressed version

## 1.0.16 (12 October 2011)

  - Updated to jQuery 1.6.4
  - Updated to jQuery UI 1.8.16

## 1.0.15 (12 October 2011)

  - Updated to latest jquery-ujs
    - Fixed formInputClickSelector `button[type]` for IE7
    - Copy target attribute to generated form for `a[data-method]` links
    - Return true (abort ajax) for ctrl- and meta-clicks on remote links
    - Use jQuery `.prop()` for disabling/enabling elements

## 1.0.14 (08 September 2011)

  - Updated to latest jquery-ujs
    - Added `disable-with` support for links
    - minor bug fixes
    - Added `data-remote` support for change events of all input types
  - Added install generator for Rails 3.1 with instructional message

## 1.0.13 (11 August 2011)

  - Updated to latest jquery-ujs with `novalidate` support
  - No more support for jquery older than v1.6

## 1.0.12 (23 June 2011)

  - Updated to latest jquery-ujs with 'blank form action' and
    data-remote support for select elements

## 1.0.11 (15 June 2011)

  - Updated to latest jqueyr-ujs with cross-domain support

[See jquery-ujs issue 167](https://github.com/rails/jquery-ujs/pull/167) for relevant discussion

## 1.0.10 (13 June 2011)

  - Updated to latest jqueyr-ujs with bug fixes

## 1.0.9 (25 May 2011)

  - Merged with new rails repo (3.1 fix)

## 1.0.8 (25 May 2011)

  - Updated to latest jquery-ujs with `[disabled][required]` fix

## 1.0.7 (21 May 2011)

  - Fix assert_select_jquery's bad call to unescape_rjs

## 1.0.6 (21 May 2011)

  - Updated to latest jquery-ujs with `data-params` support

## 1.0.5 (17 May 2011)

  - Updated to latest jquery-ujs
  - Remove old rails.js in Rails 3.0 generator

## 1.0.4 (17 May 2011)

  - Fix exception in Rails 3.0 generator

## 1.0.3 (17 May 2011)

  - Update to jQuery 1.6.1
  - Remove useless --version generator option

## 1.0.2 (12 May 2011)

  - Fix Rails 3.0 now that rails.js is named jquery_ujs.js

## 1.0.1 (10 May 2011)

  - Stop downloading rails.js from GitHub
  - Vendor jQuery UI for those who want it
  - Fix assert_select_jquery now that Rails 3.1 has no RJS at all
  - Fix rails dependency to just be railties

## 1.0.rc (3 May 2011)

  - Rails 3.1 asset pipeline edition
  - Removes generators and railties
  - Just provides jquery.js and jquery_ujs.js
  - Still compatible with Rails 3.0 via the old generator code

## 0.2.7 (5 February 2011)

  - Updated to use jQuery 1.5 by default

## 0.2.6 (1 December 2010)

Feature:

  - Updated to use jQuery 1.4.4 by default

## 0.2.5 (4 November 2010)

Bugfix:

  - Download JQuery Rails UJS via HTTPS since Github is now HTTPS only

## 0.2.4 (16 October 2010)

Features:

  - Updated to use the new jQuery 1.4.3 by default, with the IE .live() bug fixed
  - Always download the newest 1.x release of jQuery UI
  - Try to install unknown versions of jQuery, with fallback to the default
  - Print informative messages in the correct Generator style

## 0.2.3 (13 October 2010)

Features:

  - Support Edge Rails 3.1 by depending on Rails ~>3.0
  - Add Sam Ruby's assert_select_jquery test helper method
  - Use jquery.min only in production (and not in the test env)

## 0.2.2 (8 October 2010)

Feature:

  - Depend on Rails >=3.0 && <4.0 for edge Rails compatibility

## 0.2.1 (2 October 2010)

Bugfix:

  - Default to jQuery 1.4.1 as recommended by jQuery-ujs
    due to a bug in 1.4.2 (http://jsbin.com/uboxu3/7/)

## 0.2 (2 October 2010)

Features:

  - Allow specifying which version of jQuery to install
  - Add generator tests (thanks, Louis T.)
  - Automatically use non-minified JS in development mode

## 0.1.3 (16 September 2010)

Bugfix:

  - allow javascript :defaults tag to be overridden

## 0.1.2 (18 August 2010)

Bugfix:

  - check for jQueryUI in the right place

## 0.1.1 (16 August 2010)

Bugfix:

  - fix generator by resolving namespace conflict between Jquery::Rails and ::Rails
