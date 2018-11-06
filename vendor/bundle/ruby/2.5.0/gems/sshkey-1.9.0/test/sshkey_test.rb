require 'test/unit'
require 'sshkey'

class SSHKeyTest < Test::Unit::TestCase
  SSH_PRIVATE_KEY1 = <<-EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArfTA/lKVR84IMc9ZzXOCHr8DVtR8hzWuEVHF6KElavRHlk14
g0SZu3m908Ejm/XF3EfNHjX9wN+62IMA0QBxkBMFCuLF+U/oeUs0NoDdAEKxjj4n
6lq6Ss8aLct+anMy7D1jwvOLbcwV54w1d5JDdlZVdZ6AvHm9otwJq6rNpDgdmXY4
HgC2nM9csFpuy0cDpL6fdJx9lcNL2RnkRC4+RMsIB+PxDw0j3vDi04dYLBXMGYjy
eGH+mIFpL3PTPXGXwL2XDYXZ2H4SQX6bOoKmazTXq6QXuEB665njh1GxXldoIMcS
shoJL0hrk3WrTOG22N2CQA+IfHgrXJ+A+QUzKQIBIwKCAQBAnLy2O+5N3s/X/I8R
y9E+nrgY79Z7XRTEmrc5JelTnI+eOggwwbVxhP1dR7zE5kItPz2O4NqYGJXbY9u7
V++qiri65oQMJP6Tc7ROwiYzS/jObtugMFPSpLHzwJyrMho6fTOuz3zuRH0qHiJ8
3o4WAs9I8brJqY+UQxmI56t3gfHcX4nRhueyUvmEdDG+4Mob21wED1GD5ENh9ebX
UiuYkeROqd+lfBUkWoxUXi2fjRMSRt7n3bq59pyZQCwKiShIVaonciV8xAAlNvhI
RBzYvXbQ47YgsTmcW4Srlv0j/Oij2/RaDhkJtaXyPkqw9k4B8oCaX3C2x4sdhcwa
iLU7AoGBANb4Rmz1w4wfZSnu/HlW4G0Us+AWVEX+6zePoOartP5Pe5t3XhHW7vpi
YoB4ecqhz4Y1LoYZL07cSsQZHfntUV4eh/apuo/5slrhDkk0ewJkUh6SKLOFNv6Q
7iJnmtzzRovW1MQPa0NeInsUrZYe4B4iGZmK4yEr9+c7IQCPFQvVAoGBAM8ofVgb
gzDYY2uX1lvU9bGAHqA/qNJHcYZBu5AZr7bkZC1GlSKh93ppczdQhiZmj2FQr09R
Z5GgKIlSWk8MYC+kYq7l5r2O42g3Unp+i1Zc5KCYUWYpyeE/jfl5IFJFQJFVtdB1
JlsFxruQIF/HuTzY6D+zF8GzK/T5ZQwigBgFAoGAGJFnImU663FNY+DMZaOHXOxs
VB/PHfE/dBBqKP2uSPMkEcR/x4ZHMo7mr5i9dj5g3CNVxi7Dk/vrSZx4dFWi5i9f
/u7TfisqU4dvWNLMOsmi/C32BeNWvgHvVGOcq4mEZ8DH2+SBSYcZ4i4/uWKdRUW5
yGek7dkjpWXX4s6GD/sCgYEAiCHr+BIUYe1Ipcotx1FuQXFzNhs0bO0et0/EZgJA
RPx8WERTX+bHMy9aV4yv7VlW6C21CDzPB+zncC7NoakMAgzwZE3vZp+6AqgDAAoD
ywnYEcMuLTFnaCJzPYocjdW8t0bz0iEZNIAjgpHpY4M/Np0q6Af5qyyZOpVCZw9b
fX8CgYEAqFpBwetp78UfwvWyKkfN56cY8EaC7gMkwE4gnXsByrqW0f/Shf5ofpO1
kCMav5GhplRYcF3mUO9xiAPx1FxWj/MjeevkmmugIrcYi5OpGu70KoaBmCmb5uV6
zJLsX4h3i0JFdIOaECZEOXhPA7btQT8Vvznj8cHFeeronqdFWf0=
-----END RSA PRIVATE KEY-----
EOF
  SSH_PRIVATE_KEY2 = <<-EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxl6TpN7uFiY/JZ8qDnD7UrxDP+ABeh2PVg8Du1LEgXNk0+YW
CeP5S6oHklqaWeDlbmAs1oHsBwCMAVpMa5tgONOLvz4JgwgkiqQEbKR8ofWJ+LAD
UElvqRVGmGiNEMLI6GJWeneL4sjmbb8d6U+M53c6iWG0si9XE5m7teBQSsCl0Tk3
qMIkQGw5zpJeCXjZ8KpJhIJRYgexFkGgPlYRV+UYIhxpUW90t0Ra5i6JOFYwq98k
5S/6SJIZQ/A9F4JNzwLw3eVxZj0yVHWxkGz1+TyELNY1kOyMxnZaqSfGzSQJTrnI
XpdweVHuYh1LtOgedRQhCyiELeSMGwio1vRPKwIBIwKCAQEAiAZWnPCjQmNegDKg
fu5jMWsmzLbccP5TqLnWrFYDFvAKn+46/3fA421HBUVxJ7AoS6+pt6mL54tYsHhu
6rOvsfAlT/AGhbxw1Biyk6P9sOLiRCDsVE+dBjp5jRR9/N1WkLh10FH5hZETCW0b
0y88DG8DkWeR2UUIgngLr+pFr5jV/e4nvA5QpvbNscOwoiR7sFsMGLcMgM2fT4Hj
ZZovcGQMrDr6AG+y0/Vdf9wX22j+XKj7huIqM3GZvyqGPqJnP9sOKkPcuTck8Wx3
55BX675RVdoW9OTcHbUh3qHcCND4d9WZqHarW/a7XBdIiuRmC2kBX5WBmVXnm/RF
bvxoCwKBgQDqyVNWwm98gIw7LS8dR6Ec7t3kOeLNo/rtNTszo631yZ4hqdwgYR3Q
q6rhjufsVVRLVzfTDXucbhZ5h+UB9wXAM49ZPxKNw+ddHsRbhCuIWUl/iO8E/Aub
H3eZupo73N9JGa4STFw056ejOQrTTCMf0M316V4wgFAXOZeHEErxSQKBgQDYSuqR
nr3Hdw1n/iXfKrfd9fJI++nm14uQ4mkA+9HrtQpj/RTxr66/QSj7p3r6GF4dDYY4
XaqK+iCfhUKMr8+3CP7NoS/saZAUqvMnL+RCvX14sV55xRMwplaaNIwqDhQAhkmL
UeOBq40kmBsunjfp06JedmWhWKHYc1eR2iPw0wKBgA1qlwxFn/h8X8jeArE3Swj3
tOh4VhphJEgRq5yNAqBUqfNLiOvoSti5WjjGVmVGtFwTnMo7SOReD+mv/nUkDvUK
QrSkhLeky2RoKHpCER279ZJCVs0Vt4U0/4UgmxldFBLORHYS/fRlAkPXX7RNflmW
5zKfnvt1C+QR62bNuyO7AoGBAI4imiUtzStOPAKCcKiYajLGMYBrB2vPePjPTFEa
gqI1JBXSMlWt9n2uegR1X3El9LQBkrdTfrMZZeUrr2PD/Ybop3EvaKKrxRTlXfUu
GagzYRTMVAbgl5T/l/7vVMst0qFCTZYRPbucnpRj9Jr6QgAOuygh6wOgpN6yMjtG
NOAVAoGACIdfR5oZ4tvNIeqjtLF83HmUJARv86eMmjqgiQTFcZS3A8vk5y05STxX
HU3kTCfT6sypRi9zDQafIIyqYFgaOezr2eRRFRojQZqzHjtuFUeKLrKf7R9bzwwx
DPlNgYq8p4FOY5ZOL/ZOxUHW4vKRewURJttnxzw+LEy0T1FyAE0=
-----END RSA PRIVATE KEY-----
EOF
  SSH_PRIVATE_KEY3 = <<-EOF
-----BEGIN DSA PRIVATE KEY-----
MIIBvAIBAAKBgQC8lcuXcFcIC9wsV87L6PAwYefKgK0CwTSD1v3/aabZsu4w+UF8
zsPtdsNP8+JWfOp3KFbrUTH+ODgAXF/aL4UZfpbsQe446ZFV8v6dmWqj23sk0FLX
U5l2tsuJ9OdyXetVXjBvoiz+/r4k/iG/esvWlVGEHwq5eYXgQ1GfXABY3QIVAMVe
c7skmkUrCR6iivgZYYe3PQPZAoGBAKnpdEVATtDGOW9w2evSf5kc1InzdTurcJOH
q9qYdCaa8rlMGaIS6XFWcKqBlpj0Mv2R5ldW90bU/RllGvh1KinTIRVTsf4qtZIV
Xy4vN8IYzDL1493nKndMsxsRh50rI1Snn2tssAix64eJ5VFSGlyOYEKYDMlWzHK6
Jg3tVmc6AoGBAIwTRPAEcroqOzaebiVspFcmsXxDQ4wXQZQdho1ExW6FKS8s7/6p
ItmZYXTvJDwLXgq2/iK1fRRcKk2PJEaSuJR7WeNGsJKfWmQ2UbOhqA3wWLDazIZt
cMKjFzD0hM4E8qgjHjMvKDE6WgT6SFP+tqx3nnh7pJWwsbGjSMQexpyRAhQLhz0l
GzM8qwTcXd06uIZAJdTHIQ==
-----END DSA PRIVATE KEY-----
EOF

  SSH_PUBLIC_KEY1 = 'AAAAB3NzaC1yc2EAAAABIwAAAQEArfTA/lKVR84IMc9ZzXOCHr8DVtR8hzWuEVHF6KElavRHlk14g0SZu3m908Ejm/XF3EfNHjX9wN+62IMA0QBxkBMFCuLF+U/oeUs0NoDdAEKxjj4n6lq6Ss8aLct+anMy7D1jwvOLbcwV54w1d5JDdlZVdZ6AvHm9otwJq6rNpDgdmXY4HgC2nM9csFpuy0cDpL6fdJx9lcNL2RnkRC4+RMsIB+PxDw0j3vDi04dYLBXMGYjyeGH+mIFpL3PTPXGXwL2XDYXZ2H4SQX6bOoKmazTXq6QXuEB665njh1GxXldoIMcSshoJL0hrk3WrTOG22N2CQA+IfHgrXJ+A+QUzKQ=='
  SSH_PUBLIC_KEY2 = 'AAAAB3NzaC1yc2EAAAABIwAAAQEAxl6TpN7uFiY/JZ8qDnD7UrxDP+ABeh2PVg8Du1LEgXNk0+YWCeP5S6oHklqaWeDlbmAs1oHsBwCMAVpMa5tgONOLvz4JgwgkiqQEbKR8ofWJ+LADUElvqRVGmGiNEMLI6GJWeneL4sjmbb8d6U+M53c6iWG0si9XE5m7teBQSsCl0Tk3qMIkQGw5zpJeCXjZ8KpJhIJRYgexFkGgPlYRV+UYIhxpUW90t0Ra5i6JOFYwq98k5S/6SJIZQ/A9F4JNzwLw3eVxZj0yVHWxkGz1+TyELNY1kOyMxnZaqSfGzSQJTrnIXpdweVHuYh1LtOgedRQhCyiELeSMGwio1vRPKw=='
  SSH_PUBLIC_KEY3 = 'AAAAB3NzaC1kc3MAAACBALyVy5dwVwgL3CxXzsvo8DBh58qArQLBNIPW/f9pptmy7jD5QXzOw+12w0/z4lZ86ncoVutRMf44OABcX9ovhRl+luxB7jjpkVXy/p2ZaqPbeyTQUtdTmXa2y4n053Jd61VeMG+iLP7+viT+Ib96y9aVUYQfCrl5heBDUZ9cAFjdAAAAFQDFXnO7JJpFKwkeoor4GWGHtz0D2QAAAIEAqel0RUBO0MY5b3DZ69J/mRzUifN1O6twk4er2ph0JpryuUwZohLpcVZwqoGWmPQy/ZHmV1b3RtT9GWUa+HUqKdMhFVOx/iq1khVfLi83whjMMvXj3ecqd0yzGxGHnSsjVKefa2ywCLHrh4nlUVIaXI5gQpgMyVbMcromDe1WZzoAAACBAIwTRPAEcroqOzaebiVspFcmsXxDQ4wXQZQdho1ExW6FKS8s7/6pItmZYXTvJDwLXgq2/iK1fRRcKk2PJEaSuJR7WeNGsJKfWmQ2UbOhqA3wWLDazIZtcMKjFzD0hM4E8qgjHjMvKDE6WgT6SFP+tqx3nnh7pJWwsbGjSMQexpyR'

  SSH_PUBLIC_KEY_ED25519   = 'AAAAC3NzaC1lZDI1NTE5AAAAIBrNsRCISAtKXV5OVxqV6unVcdis5Uh3oiC6B7CMB7HQ'
  SSH_PUBLIC_KEY_ECDSA_256 = 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHJFDZ5qymZfIzoJcxYeu3C9HjJ08QAbqR28C2zSMLwcb3ZzWdRApnj6wEgRvizsBmr9zyPKb2u5Rp0vjJtQcZo='
  SSH_PUBLIC_KEY_ECDSA_384 = 'AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBP+GtUCOR8aW7xTtpkbJS0qqNZ98PgbUNtTFhE+Oe+khgoFMX+o0JG5bckVuvtkRl8dr+63kUK0QPTtzP9O5yixB9CYnB8CgCgYo1FCXZuJIImf12wW5nWKglrCH4kV1Qg=='
  SSH_PUBLIC_KEY_ECDSA_521 = 'AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACsunidnIZ77AjCHSDp/xknLGDW3M0Ia7nxLdImmp0XGbxtbwYm2ga5XUzV9dMO9wF9ICC3OuH6g9DtGOBNPru1PwFDjaPISGgm0vniEzWazLsvjJVLThOA3VyYLxmtjm0WfS+/DfxgWVS6oeCTnDjjoVVpwU/fDbUbYPPRZI84/hOGNA=='

  KEY1_MD5_FINGERPRINT = "2a:89:84:c9:29:05:d1:f8:49:79:1c:ba:73:99:eb:af"
  KEY2_MD5_FINGERPRINT = "3c:af:74:87:cc:cc:a1:12:05:1a:09:b7:7b:ce:ed:ce"
  KEY3_MD5_FINGERPRINT = "14:f6:6a:12:96:be:44:32:e6:3c:77:43:94:52:f5:7a"
  ED25519_MD5_FINGERPRINT = "6f:1a:8a:c1:4f:13:5c:36:6e:3f:be:eb:49:3b:8e:3e"
  ECDSA_256_MD5_FINGERPRINT = "d9:3a:7f:de:b2:65:04:ac:62:05:1a:1e:97:e9:2b:9d"

  KEY1_SHA1_FINGERPRINT = "e4:f9:79:f2:fe:d6:be:2d:ef:2e:c2:fa:aa:f8:b0:17:34:fe:0d:c0"
  KEY2_SHA1_FINGERPRINT = "9a:52:78:2b:6b:cb:39:b7:85:ed:90:8a:28:62:aa:b3:98:88:e6:07"
  KEY3_SHA1_FINGERPRINT = "15:68:c6:72:ac:18:d1:fc:ab:a2:b7:b5:8c:d1:fe:8f:b9:ae:a9:47"
  ED25519_SHA1_FINGERPRINT = "57:41:7c:d0:e2:53:28:87:7e:87:53:d4:69:ef:ef:63:ec:c0:0e:5e"
  ECDSA_256_SHA1_FINGERPRINT = "94:e8:92:2b:1b:ec:49:de:ff:85:ea:6e:10:d6:8d:87:7a:67:40:ee"

  KEY1_SHA256_FINGERPRINT = "js3llFehloxCfsVuDw5xu3NtS9AOAxcXY8WL6vkDIts="
  KEY2_SHA256_FINGERPRINT = "23f/6U/LdxIFx1CQFKHylw76n+LIHYoY4nRxKcFoos4="
  KEY3_SHA256_FINGERPRINT = "mPqEPQlOPGORrTJrU17sPax1jOqeutZja6MOsFIca+8="
  ED25519_SHA256_FINGERPRINT = "gyzHUKl1eO8Bk1Cvn4joRgxRlXo1+1HJ3Vho/hAtKEg="
  ECDSA_256_SHA256_FINGERPRINT = "ncy2crhoL44R58GCZPQ5chPRrjlQKKgu07FDNelDmdk="

  KEY1_RANDOMART = <<-EOF.rstrip
+--[ RSA 2048]----+
|o+ o..           |
|..+.o            |
| ooo             |
|.++. o           |
|+o+ +   S        |
|.. + o .         |
|  . + .          |
|   . .           |
|    Eo.          |
+-----------------+
EOF

  KEY2_RANDOMART = <<-EOF.rstrip
+--[ RSA 2048]----+
|  ..o..          |
|   ..+ .         |
|    o   .        |
|     . o         |
|    . o S .      |
|     + o O o     |
|      + + O .    |
|       = o .     |
|       .E        |
+-----------------+
EOF

  KEY3_RANDOMART = <<-EOF.rstrip
+--[ DSA 1024]----+
|       .=o.      |
|      .+.o .     |
|    + =.o . .    |
|   + * + . .     |
|    + = S . E    |
|     + = . .     |
|      .          |
|                 |
|                 |
+-----------------+
EOF

  SSH2_PUBLIC_KEY1 = <<-EOF.rstrip
---- BEGIN SSH2 PUBLIC KEY ----
Comment: me@example.com
AAAAB3NzaC1yc2EAAAABIwAAAQEArfTA/lKVR84IMc9ZzXOCHr8DVtR8hzWuEVHF6KElav
RHlk14g0SZu3m908Ejm/XF3EfNHjX9wN+62IMA0QBxkBMFCuLF+U/oeUs0NoDdAEKxjj4n
6lq6Ss8aLct+anMy7D1jwvOLbcwV54w1d5JDdlZVdZ6AvHm9otwJq6rNpDgdmXY4HgC2nM
9csFpuy0cDpL6fdJx9lcNL2RnkRC4+RMsIB+PxDw0j3vDi04dYLBXMGYjyeGH+mIFpL3PT
PXGXwL2XDYXZ2H4SQX6bOoKmazTXq6QXuEB665njh1GxXldoIMcSshoJL0hrk3WrTOG22N
2CQA+IfHgrXJ+A+QUzKQ==
---- END SSH2 PUBLIC KEY ----
EOF

  SSH2_PUBLIC_KEY2 = <<-EOF.rstrip
---- BEGIN SSH2 PUBLIC KEY ----
AAAAB3NzaC1yc2EAAAABIwAAAQEAxl6TpN7uFiY/JZ8qDnD7UrxDP+ABeh2PVg8Du1LEgX
Nk0+YWCeP5S6oHklqaWeDlbmAs1oHsBwCMAVpMa5tgONOLvz4JgwgkiqQEbKR8ofWJ+LAD
UElvqRVGmGiNEMLI6GJWeneL4sjmbb8d6U+M53c6iWG0si9XE5m7teBQSsCl0Tk3qMIkQG
w5zpJeCXjZ8KpJhIJRYgexFkGgPlYRV+UYIhxpUW90t0Ra5i6JOFYwq98k5S/6SJIZQ/A9
F4JNzwLw3eVxZj0yVHWxkGz1+TyELNY1kOyMxnZaqSfGzSQJTrnIXpdweVHuYh1LtOgedR
QhCyiELeSMGwio1vRPKw==
---- END SSH2 PUBLIC KEY ----
EOF

  SSH2_PUBLIC_KEY3 = <<-EOF.rstrip
---- BEGIN SSH2 PUBLIC KEY ----
Comment: 1024-bit DSA with provided comment
x-private-use-header: some value that is long enough to go to wrap aro\\
und to a new line.
AAAAB3NzaC1kc3MAAACBALyVy5dwVwgL3CxXzsvo8DBh58qArQLBNIPW/f9pptmy7jD5QX
zOw+12w0/z4lZ86ncoVutRMf44OABcX9ovhRl+luxB7jjpkVXy/p2ZaqPbeyTQUtdTmXa2
y4n053Jd61VeMG+iLP7+viT+Ib96y9aVUYQfCrl5heBDUZ9cAFjdAAAAFQDFXnO7JJpFKw
keoor4GWGHtz0D2QAAAIEAqel0RUBO0MY5b3DZ69J/mRzUifN1O6twk4er2ph0JpryuUwZ
ohLpcVZwqoGWmPQy/ZHmV1b3RtT9GWUa+HUqKdMhFVOx/iq1khVfLi83whjMMvXj3ecqd0
yzGxGHnSsjVKefa2ywCLHrh4nlUVIaXI5gQpgMyVbMcromDe1WZzoAAACBAIwTRPAEcroq
OzaebiVspFcmsXxDQ4wXQZQdho1ExW6FKS8s7/6pItmZYXTvJDwLXgq2/iK1fRRcKk2PJE
aSuJR7WeNGsJKfWmQ2UbOhqA3wWLDazIZtcMKjFzD0hM4E8qgjHjMvKDE6WgT6SFP+tqx3
nnh7pJWwsbGjSMQexpyR
---- END SSH2 PUBLIC KEY ----
EOF

  def setup
    @key1 = SSHKey.new(SSH_PRIVATE_KEY1, :comment => "me@example.com")
    @key2 = SSHKey.new(SSH_PRIVATE_KEY2, :comment => "me@example.com")
    @key3 = SSHKey.new(SSH_PRIVATE_KEY3, :comment => "me@example.com")
    @key_without_comment = SSHKey.new(SSH_PRIVATE_KEY1)
  end

  def test_generator_with_no_args
    assert_kind_of SSHKey, SSHKey.generate
  end

  def test_generator_with_comment
    assert_equal "foo", SSHKey.generate(:comment => "foo").comment
  end

  def test_generator_with_type
    assert_equal "dsa", SSHKey.generate(:type => "dsa").type
  end

  def test_generator_with_passphrase
    assert_equal "password", SSHKey.generate(:passphrase => "password").passphrase
  end

  def test_private_key1
    assert_equal SSH_PRIVATE_KEY1, @key1.private_key
    assert_equal SSH_PRIVATE_KEY1, @key1.rsa_private_key
  end

  def test_private_key2
    assert_equal SSH_PRIVATE_KEY2, @key2.private_key
    assert_equal SSH_PRIVATE_KEY2, @key2.rsa_private_key
  end

  def test_private_key3
    assert_equal SSH_PRIVATE_KEY3, @key3.private_key
    assert_equal SSH_PRIVATE_KEY3, @key3.dsa_private_key
  end

  def test_ssh_public_key_decoded1
    assert_equal Base64.decode64(SSH_PUBLIC_KEY1), @key1.send(:ssh_public_key_conversion)
  end

  def test_ssh_public_key_decoded2
    assert_equal Base64.decode64(SSH_PUBLIC_KEY2), @key2.send(:ssh_public_key_conversion)
  end

  def test_ssh_public_key_decoded3
    assert_equal Base64.decode64(SSH_PUBLIC_KEY3), @key3.send(:ssh_public_key_conversion)
  end

  def test_ssh_public_key_encoded1
    assert_equal SSH_PUBLIC_KEY1, Base64.encode64(@key1.send(:ssh_public_key_conversion)).gsub("\n", "")
  end

  def test_ssh_public_key_encoded2
    assert_equal SSH_PUBLIC_KEY2, Base64.encode64(@key2.send(:ssh_public_key_conversion)).gsub("\n", "")
  end

  def test_ssh_public_key_encoded3
    assert_equal SSH_PUBLIC_KEY3, Base64.encode64(@key3.send(:ssh_public_key_conversion)).gsub("\n", "")
  end

  def test_ssh_public_key_output
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    expected2 = "ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    expected3 = "ssh-dss #{SSH_PUBLIC_KEY3} me@example.com"
    expected4 = "ssh-rsa #{SSH_PUBLIC_KEY1}"
    assert_equal expected1, @key1.ssh_public_key
    assert_equal expected2, @key2.ssh_public_key
    assert_equal expected3, @key3.ssh_public_key
    assert_equal expected4, @key_without_comment.ssh_public_key
  end

  def test_ssh2_public_key_output
    expected1 = SSH2_PUBLIC_KEY1
    expected2 = SSH2_PUBLIC_KEY2
    expected3 = SSH2_PUBLIC_KEY3
    public_key1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    public_key2 = "ssh-rsa #{SSH_PUBLIC_KEY2}"
    public_key3 = "ssh-rsa #{SSH_PUBLIC_KEY3} 1024-bit DSA with provided comment"

    assert_equal expected1, @key1.ssh2_public_key
    assert_equal expected2, @key2.ssh2_public_key({})
    assert_equal expected3, @key3.ssh2_public_key({'Comment' => '1024-bit DSA with provided comment',
      'x-private-use-header' => 'some value that is long enough to go to wrap around to a new line.'})
  end

  def test_public_key_directives
    assert_equal [], SSHKey.generate.directives

    @key1.directives = "no-pty"
    assert_equal ["no-pty"], @key1.directives

    @key1.directives = ["no-pty"]
    assert_equal ["no-pty"], @key1.directives

    @key1.directives = [
      "no-port-forwarding",
      "no-X11-forwarding",
      "no-agent-forwarding",
      "no-pty",
      "command='/home/user/bin/authprogs'"
    ]
    expected1 = "no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command='/home/user/bin/authprogs' ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    assert_equal expected1, @key1.ssh_public_key
    assert SSHKey.valid_ssh_public_key?(expected1)

    @key2.directives = "no-pty"
    expected2 = "no-pty ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    assert_equal expected2, @key2.ssh_public_key
    assert SSHKey.valid_ssh_public_key?(expected2)
  end

  def test_ssh_public_key_validation
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    expected2 = "ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    expected3 = "ssh-dss #{SSH_PUBLIC_KEY3} me@example.com"
    expected4 = "ssh-rsa #{SSH_PUBLIC_KEY1}"
    expected5 = %Q{from="trusted.eng.cam.ac.uk",no-port-forwarding,no-pty ssh-rsa #{SSH_PUBLIC_KEY1}}
    invalid1  = "ssh-rsa #{SSH_PUBLIC_KEY1}= me@example.com"
    invalid2  = "ssh-rsa #{SSH_PUBLIC_KEY2}= me@example.com"
    invalid3  = "ssh-dss #{SSH_PUBLIC_KEY3}= me@example.com"
    invalid4  = "ssh-rsa A#{SSH_PUBLIC_KEY1}"
    invalid5  = "ssh-rsa #{SSH_PUBLIC_KEY3} me@example.com"

    assert SSHKey.valid_ssh_public_key?(expected1)
    assert SSHKey.valid_ssh_public_key?(expected2)
    assert SSHKey.valid_ssh_public_key?(expected3)
    assert SSHKey.valid_ssh_public_key?(expected4)
    assert SSHKey.valid_ssh_public_key?(expected5)

    assert !SSHKey.valid_ssh_public_key?(invalid1)
    assert !SSHKey.valid_ssh_public_key?(invalid2)
    assert !SSHKey.valid_ssh_public_key?(invalid3)
    assert !SSHKey.valid_ssh_public_key?(invalid4)
    assert !SSHKey.valid_ssh_public_key?(invalid5)
  end

  def test_ssh_public_key_validation_elliptic
    assert SSHKey.valid_ssh_public_key?("ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519} me@example.com")
    assert SSHKey.valid_ssh_public_key?("ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256}")
    assert SSHKey.valid_ssh_public_key?("ecdsa-sha2-nistp384 #{SSH_PUBLIC_KEY_ECDSA_384} me@example.com")
    assert SSHKey.valid_ssh_public_key?(%Q{from="trusted.eng.cam.ac.uk",no-port-forwarding,no-pty ecdsa-sha2-nistp521 #{SSH_PUBLIC_KEY_ECDSA_521} me@example.com})

    assert !SSHKey.valid_ssh_public_key?("ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519}= me@example.com") # bad base64
    assert !SSHKey.valid_ssh_public_key?("ssh-ed25519 #{SSH_PUBLIC_KEY_ECDSA_384} me@example.com") # mismatched key format
    assert !SSHKey.valid_ssh_public_key?("ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_384} me@example.com") # mismatched key format
    assert !SSHKey.valid_ssh_public_key?("ssh-ed25519 asdf me@example.com") # gibberish key data
    assert !SSHKey.valid_ssh_public_key?("ecdsa-sha2-nistp256 asdf me@example.com") # gibberish key data
  end

  def test_ssh_public_key_validation_with_newlines
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1}\n"
    expected2 = "ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519} me@example.com\n"
    invalid1  = "ssh-rsa #{SSH_PUBLIC_KEY1}\nme@example.com"
    invalid2  = "ssh-rsa #{SSH_PUBLIC_KEY1}\n me@example.com"
    invalid3  = "ssh-rsa #{SSH_PUBLIC_KEY1} \nme@example.com"
    invalid4  = "ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256}\nme@example.com"

    assert SSHKey.valid_ssh_public_key?(expected1)
    assert SSHKey.valid_ssh_public_key?(expected2)

    assert !SSHKey.valid_ssh_public_key?(invalid1)
    assert !SSHKey.valid_ssh_public_key?(invalid2)
    assert !SSHKey.valid_ssh_public_key?(invalid3)
    assert !SSHKey.valid_ssh_public_key?(invalid4)
  end

  def test_ssh_public_key_bits
    expected1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    expected2 = "ssh-rsa #{SSH_PUBLIC_KEY2} me@example.com"
    expected3 = "ssh-dss #{SSH_PUBLIC_KEY3} me@example.com"
    expected4 = "ssh-rsa #{SSH_PUBLIC_KEY1}"
    expected5 = %Q{from="trusted.eng.cam.ac.uk",no-port-forwarding,no-pty ssh-rsa #{SSH_PUBLIC_KEY1}}
    invalid1  = "#{SSH_PUBLIC_KEY1} me@example.com"

    assert_equal 2048, SSHKey.ssh_public_key_bits(expected1)
    assert_equal 2048, SSHKey.ssh_public_key_bits(expected2)
    assert_equal 1024, SSHKey.ssh_public_key_bits(expected3)
    assert_equal 2048, SSHKey.ssh_public_key_bits(expected4)
    assert_equal 2048, SSHKey.ssh_public_key_bits(expected5)
    assert_equal 512,  SSHKey.ssh_public_key_bits(SSHKey.generate(:bits => 512).ssh_public_key)

    exception1 = assert_raises(SSHKey::PublicKeyError) { SSHKey.ssh_public_key_bits( expected1.gsub('A','.') ) }
    exception2 = assert_raises(SSHKey::PublicKeyError) { SSHKey.ssh_public_key_bits( expected1[0..-20] ) }
    exception3 = assert_raises(SSHKey::PublicKeyError) { SSHKey.ssh_public_key_bits(invalid1) }

    assert_equal( "validation error",          exception1.message )
    assert_equal( "byte array too short",      exception2.message )
    assert_equal( "cannot determine key type", exception3.message )
  end

  def test_ssh2_public_key_bits
    public_key1 = "ssh-rsa #{SSH_PUBLIC_KEY1} me@example.com"
    public_key2 = "ssh-rsa #{SSH_PUBLIC_KEY2}"
    public_key3 = "ssh-dss #{SSH_PUBLIC_KEY3} 1024-bit DSA with provided comment"

    assert_equal(SSH2_PUBLIC_KEY1, SSHKey.ssh_public_key_to_ssh2_public_key(public_key1))
    assert_equal(SSH2_PUBLIC_KEY2, SSHKey.ssh_public_key_to_ssh2_public_key(public_key2))
    assert_equal(SSH2_PUBLIC_KEY2, SSHKey.ssh_public_key_to_ssh2_public_key(public_key2, {}))
    assert_equal(SSH2_PUBLIC_KEY3, SSHKey.ssh_public_key_to_ssh2_public_key(public_key3, {'Comment' => '1024-bit DSA with provided comment', 'x-private-use-header' => 'some value that is long enough to go to wrap around to a new line.'}))
end

  def test_exponent
    assert_equal 35, @key1.key_object.e.to_i
    assert_equal 35, @key2.key_object.e.to_i
  end

  def test_modulus
    assert_equal 21959919395955180268707532246136630338880737002345156586705317733493418045367765414088155418090419238250026039981229751319343545922377196559932805781226688384973919515037364518167604848468288361633800200593870224270802677578686553567598208927704479575929054501425347794297979215349516030584575472280923909378896367886007339003194417496761108245404573433556449606964806956220743380296147376168499567508629678037211105349574822849913423806275470761711930875368363589001630573570236600319099783704171412637535837916991323769813598516411655563604244942820475880695152610674934239619752487880623016350579174487901241422633, @key1.key_object.n.to_i
    assert_equal 25041821909255634338594631709409930006900629565221199423527442992482865961613864019776541767273966885435978473182530882048894721263421597979360058644777295324028381353356143013803778109979347540540538361684778724178534886189535456555760676722894784592989232554962714835255398111716791175503010379276254975882143986862239829255392231575481418297073759441882528318940783011390002193682320028951031205422825662402426266933458263786546846123394508656926946338411182471843223455365249418245551220933173115037201835242811305615780499842939975996344432437312062643436832423359634116147870328774728910949553186982115987967787, @key2.key_object.n.to_i
  end

  def test_fingerprint
    assert_equal KEY1_MD5_FINGERPRINT, @key1.md5_fingerprint
    assert_equal KEY1_MD5_FINGERPRINT, @key1.fingerprint # Aliased method
    assert_equal KEY2_MD5_FINGERPRINT, @key2.md5_fingerprint
    assert_equal KEY3_MD5_FINGERPRINT, @key3.md5_fingerprint

    assert_equal KEY1_SHA1_FINGERPRINT, @key1.sha1_fingerprint
    assert_equal KEY2_SHA1_FINGERPRINT, @key2.sha1_fingerprint
    assert_equal KEY3_SHA1_FINGERPRINT, @key3.sha1_fingerprint

    assert_equal KEY1_SHA256_FINGERPRINT, @key1.sha256_fingerprint
    assert_equal KEY2_SHA256_FINGERPRINT, @key2.sha256_fingerprint
    assert_equal KEY3_SHA256_FINGERPRINT, @key3.sha256_fingerprint

    assert_equal KEY1_MD5_FINGERPRINT, SSHKey.md5_fingerprint(SSH_PRIVATE_KEY1)
    assert_equal KEY1_MD5_FINGERPRINT, SSHKey.md5_fingerprint("ssh-rsa #{SSH_PUBLIC_KEY1}")
    assert_equal KEY2_MD5_FINGERPRINT, SSHKey.md5_fingerprint(SSH_PRIVATE_KEY2)
    assert_equal KEY2_MD5_FINGERPRINT, SSHKey.md5_fingerprint("ssh-rsa #{SSH_PUBLIC_KEY2} me@me.com")
    assert_equal KEY3_MD5_FINGERPRINT, SSHKey.md5_fingerprint(SSH_PRIVATE_KEY3)
    assert_equal KEY3_MD5_FINGERPRINT, SSHKey.md5_fingerprint("ssh-dss #{SSH_PUBLIC_KEY3}")
    assert_equal ED25519_MD5_FINGERPRINT, SSHKey.md5_fingerprint("ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519}")
    assert_equal ECDSA_256_MD5_FINGERPRINT, SSHKey.md5_fingerprint("ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256} me@me.com")

    assert_equal KEY1_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint(SSH_PRIVATE_KEY1)
    assert_equal KEY1_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint("ssh-rsa #{SSH_PUBLIC_KEY1}")
    assert_equal KEY2_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint(SSH_PRIVATE_KEY2)
    assert_equal KEY2_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint("ssh-rsa #{SSH_PUBLIC_KEY2} me@me.com")
    assert_equal KEY3_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint(SSH_PRIVATE_KEY3)
    assert_equal KEY3_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint("ssh-dss #{SSH_PUBLIC_KEY3}")
    assert_equal ED25519_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint("ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519}")
    assert_equal ECDSA_256_SHA1_FINGERPRINT, SSHKey.sha1_fingerprint("ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256} me@me.com")

    assert_equal KEY1_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint(SSH_PRIVATE_KEY1)
    assert_equal KEY1_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint("ssh-rsa #{SSH_PUBLIC_KEY1}")
    assert_equal KEY2_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint(SSH_PRIVATE_KEY2)
    assert_equal KEY2_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint("ssh-rsa #{SSH_PUBLIC_KEY2} me@me.com")
    assert_equal KEY3_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint(SSH_PRIVATE_KEY3)
    assert_equal KEY3_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint("ssh-dss #{SSH_PUBLIC_KEY3}")
    assert_equal ED25519_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint("ssh-ed25519 #{SSH_PUBLIC_KEY_ED25519}")
    assert_equal ECDSA_256_SHA256_FINGERPRINT, SSHKey.sha256_fingerprint("ecdsa-sha2-nistp256 #{SSH_PUBLIC_KEY_ECDSA_256} me@me.com")
  end

  def test_bits
    assert_equal 2048, @key1.bits
    assert_equal 2048, @key2.bits
    assert_equal 1024, @key3.bits
    assert_equal 512, SSHKey.generate(:bits => 512).bits
  end

  def test_randomart
    assert_equal KEY1_RANDOMART, @key1.randomart
    assert_equal KEY2_RANDOMART, @key2.randomart
    assert_equal KEY3_RANDOMART, @key3.randomart
  end
end

class SSHKeyEncryptedTest < Test::Unit::TestCase

  ENCRYPTED_PRIVATE_KEY = <<-EOF
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3514D8812B519059944A811726594515

fSr1v51I65MZrSs7u12nype6RH6NS15xN5FDPaPKV++EBPxysEzicU5QHDt/aHa3
t87nXkra1M400+zNgFcfi5Ga7w5SBmqEjdNgwhUV2/j1Yqqlr5c7l804OfIPxdE6
ELoWH7pen72JnlZe6gXq495W96QTg3IzIWdiKEbKJlEwrNBligqT7GB2mup8nY1D
o71R07dIrvfDy3xVgCoRjX4LKUilO6nRnwVCFRgVQTEVKclqt8NiSFGMjzv3iekR
f1fJ8Wm6CiST8zdetIXgMnHEK1KELhNeMhI/42Tn/gHPDsckBiKLtM+85OOT92wh
L9o/KUySdcsb/ld0yT/kAc99/wqNitHAqUEcLshIWDVhqoT1XK46hEuRN782AN2U
shQKirF8QFopYF+u9K2Q0mr1EsYaBWOFFBR7EiwFvEYOx+ad6qGQGPcxWhbf6eCU
D///9g1g5q8nWb80UH9Hw1aMhIA+VTlIasM6XJKmGr1LapxlrYsqRovPwkgOQg01
jhSV1fy10bbaFBwd9qTdTTVqa368/e3/TxF2VKhDaqoy5lqvRqKzGJxi3ubzDuz9
m3qRTCgy1v3XI5DgcjWt5xC5gZLHjKf79fQKRJjuEnWALahpDVWQ6PRCuqPfyph5
/vVqGHqvA53HJ9pmXz4J9qtQQ2gkYRj1m2tlRJjtGRMqnAj7bpcDKIrdLudOiWB0
FXwmsXljzPaf/SPUa+tGg7jbh+Jq+72vdpo1ijJtLXhWQAJasIbvSXOVHbZ6YhJj
vES98gJPzevqemS//C1DMrr0ci6pM9ciT2szkrg71zRacnfqrjeZUI7qHKAsRbD5
258Jj6BeFPeQSrUg8sqQdoPxVTNnVr2bOB5SNfh7gqLanPksi6Kr7XNIzsYP5Wzf
ADAElPdcRRwYc2kLVqugZTMLSn1r8rQjEyQ8/TT2QefI4ma8mCrBKgqYX+SDbhMJ
+KUrah0jCgj86z6fSNkNHaKuzvGCovZsJHXt2SoIWVYWVUz91IHPKXXycIqvf3Yj
9HFpJRAPh30MYBgiImCJjmk8tqKGn0Tc80vOsrKMlVuMIIu2eNrddrnHUzSbjIHr
tTtSDvsJ/Bn/6+Ox77U/FKg6s6/6PxOA1a+ffKkBXB/g4jS5CfGZl1owb3kX91C/
a+bcNWp07DsaTaZd/0UEL2gIvaEuCULgyIvmnBPCOY6Pc5GGegWEJne/sk7j9W4I
59YtVfcSXiovYR/QEywytfN/tfPxKfUoqNMIxLkukjFYz4Zzk5kXEeI+1lcry398
UQSaOboSDKY6boX4rWgiiqyn5LN+47eAIZPO+zsWXky16F04JpT7V7XqZPXQn7vI
pMAoPCkT4qE9Gp2CcSj2l2CoZ3ZA5lOs6Wvxuz0q1zd0uSe8O81/3rnw28DthDQO
SuzrY0HinPEFomwMGbfhosB5kOmBXEk7XbSWWHhK0QG63CYqp5caUst2Mie21b0Y
FgFTrS1VqUiqDjCmt8F8UCPQS89aFm096wqtmwDO+VWKanuHUUShtTPlYyLe1RTm
wqh1BBa05ydM0Vf1NagFB4JNT1qSIL5x4XtkOFwqcdXWYvwYfT8PkZjX/kz+W7jb
-----END RSA PRIVATE KEY-----
EOF

  DECRYPTED_PRIVATE_KEY = <<-EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA33H9u4rG0SVMzK8PFyIi30kVHvogmpKVOQL2g2tozi2GipkA
imzoCW9jIx1jo6zo0kMKCbMdJCNUc93tQxkJAAWA07WYwE9z+J6MC/3urb4Q0UAZ
orlNyN3pPP8ATFIQomd0wW/EHwbmknlJOIZY4MNUQpNJunnBAAzZyLef6+sbLzQZ
wc0/vgtmatoCxh4mZWFuFMopkMqScYDKxL30xXXPRGfJvAVWZDnY3ErJSe7uyefI
Zo/lp4tsH5XGMcFm+nLs++nJjYZ6Ud/ie1g+ZCJv5Qit1m7zCVjiJ4RVMC/4yTb7
CO8n4PhX8gR9d1DRPVvlKa1sZfQeULEIXMniKQIDAQABAoIBAQDEXS74s5rJjhgS
AP4n/E3dICK5mGMytAMDmUD+eVQfbQ7BmnhJLjA0qnjbESbRXlE1Bsk5gPjpG0tK
kAvEXan1JOD0LLDSwIBQSzUUDNLGSTQKUGS3BlX/YlVoz0h5ydzofDa1D/2wrqXO
r1vTmu1ciQvxffLbN8iOvLxfkk+uSMhqnhf/q3WVinu+VALPg8e/v3p4VbnSfP4D
eClBiMKEKRFdsa9xBxShijcX1HxjIvp3zDgb127fo2iFw09PIHUZCUo6M77iGrQY
mscoA+5q1qSyD6Btw0EkKK55ytNMC2T+KfGYV0ySwhadmM+5+G64etvNGCn/j7CU
rhuRhMlpAoGBAPiJlcWaNVw3ttlea+jllxnaCEOmG29NGWxw080XRvjSIrltPAiE
8e4FynAMx49aXKsaB8Df2WspdKBxHJgv1U0sapADwxlMO8erj2eDSRqy6bwnI4CT
T+vvo2vdmkvkV0D9RskXCi5tgTO5FYnf7CjON6JLkg83V3vzyjsKlvDzAoGBAOYn
iC50OdZ84U58wQUsvwXFuyzMQX9r+h0jL2tIDv/yYlMWg9tNt0HkGUOo7H1ZVhdL
9Z1B0Ztl2qoJipcQvhzfwdo4XwuLk7D0bOAfZo9YMbU5Jqy+rqE5yv/P4wa7ba4S
uUQYvSuv54CtiOZDFyK8dU7y9mm+no3Fvrd9RwdzAoGANzlLACctqBnxFQd37r3k
/yeFIpLsEaUN+xxu02lSqcL3WEA/UJ1JrFu5CYCtbtrjMFmOU3rpsnf5pBS+B8rJ
GGbAHtPXK+3Wcp1aNePkAHy0lswThWQ2I/SRWUxaFnbcNGKSsefeqUZHqRh9Aq+w
p7h6gCNOhvcDB1W6H7hQpaUCgYEAyBRDygaWJUVI5N+FOUduBMmhb09d/TTUKTJm
TcBF8fE30v12wVZtYqW15ODcPhhExFnverc2Tf6cukczKSKP8y/+KQPqdHHxgdrr
L2d81E6aX+4AFhpqW5SPShXiSf70WWjDkFRlV65C9dVmdq6KVVM6M9j5qHHjCmKG
6qLI9csCgYBuhFwwI9DiYvJPR1LJZnJtE0qZiTwpmCjU2LoBRsywvuBeyXtwpmIM
5IgfgXXLK5qK/+cp9047T5rzT6ndu5fNZINPzynA8tNhTtHXK8l/GT/iq8Rd6AcM
WJmIe8EnUDhHqg7Z2h5tGpX1QPMSA4G8RGPPyrcd3v0G/PZ6pFALlQ==
-----END RSA PRIVATE KEY-----
EOF

  DECRYPTED_KEY_FINGERPRINT = "2e:ba:06:b1:c7:13:37:24:6f:2d:3a:ba:45:e2:b4:78"

  def setup
    @key_encrypted = SSHKey.new(ENCRYPTED_PRIVATE_KEY, :passphrase => "password")
  end

  def test_encrypted_private_key_can_be_decrypted
    assert_equal DECRYPTED_PRIVATE_KEY, @key_encrypted.private_key
  end

  def test_encrypted_private_key_matches_when_reencrypted
    key = SSHKey.new(@key_encrypted.encrypted_private_key, :passphrase => "password")
    assert_equal DECRYPTED_PRIVATE_KEY, key.private_key
    assert_equal DECRYPTED_KEY_FINGERPRINT, key.md5_fingerprint
  end
end
