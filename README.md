# radb

Query IPv4 Ranges from RADB.net

Author: sskaje ([https://sskaje.me/](https://sskaje.me/))

# Usage


```
php query-ips.php OPTIONS 
OPTIONS:
    -d          Turn on DEBUG
    -s NAME     Set AS-SET-NAME
    -d NUMBER   Set AS-NUMBER
    -o FILE     Append output to file
    -O FILE     Overwrite output to file

```



# Examples

```
php query-ips.php -s AS-GOOGLE -d
php query-ips.php -n AS15169 -d
php query-ips.php -s AS-GOOGLE -s AS-TWITTER -d
php query-ips.php -s AS-TWITTER -n AS15169 -d
php query-ips.php -n AS15169 -d -o as15169.txt
php query-ips.php -n AS15169 -d -O as15169.txt
```

# Known AS-SET list

* AS-GOOGLE
* AS-TWITTER
* AS-FACEBOOK
* AS-HURRICANE
* AS-AMAZON
* AS-MICROSOFT
* AS-APPLE
* AS-LINODE
* AS-DIGITALOCEAN
* AS-AOL
* AS-CN
* AS-CNC
* AS-YAHOO
* AS-CLOUDFLARE
* AS-WIKIMEDIA
* AS-EBAY
* AS-CISCO
* AS-BBC
* AS-ROOT
* AS-ICI
* AS-YANDEX
* AS-RUSSIA
* AS-KDD


# EOF
