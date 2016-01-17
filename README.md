# radb

Query IPv4 Ranges from RADB.net

Author: sskaje ([https://sskaje.me/](https://sskaje.me/))

# Usage


```
php query-ips.php OPTIONS 
OPTIONS:
    -d          Turn on DEBUG. Messages are sent to STDERR.
    -s NAME     Set AS-SET-NAME
    -d NUMBER   Set AS-NUMBER
```



# Examples

```
php query-ips.php -s AS-GOOGLE -d 
php query-ips.php -n AS15169   -d 
php qury-ips.php -s AS-GOOGLE -s AS-TWITTER -d 
php query-ips.php -s AS-TWITTER -n AS15169 -d 

```

# Known AS-SET list

* AS-HURRICANE
* AS-GOOGLE
* AS-TWITTER
* AS-AMAZON
* AS-FACEBOOK
* AS-MICROSOFT
* AS-APPLE
* AS-LINODE
* AS-DIGITALOCEAN
* AS-AOL
* AS-CN


# EOF