# radb

Query IPv4 Ranges from RADB.net

Author: sskaje ([https://sskaje.me/](https://sskaje.me/))

# Usage

```
php query-ips.php AS-SET-NAME|AS-NUMBER [-d]
```

**-d**: Turn on debug messages. Messages are sent to STDERR.


# Examples

```
php query-ips.php AS-GOOGLE -d
php query-ips.php AS15169 -d
```

# EOF