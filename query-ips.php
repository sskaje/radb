<?php
/**
 * Query IPv4 Ranges from RADB.net
 *
 * @author sskaje http://sskaje.me/
 */

copyright();

if (!isset($argv[1])) {
    usage();
}

$enable_debug = false;
$query_asns = [];
$query_as_sets = [];
$output_file = '';
$overwrite = false;
$overwrite_init = false;

for ($i=1; isset($argv[$i]); $i++) {
    if ($argv[$i] == '-d') {
        $enable_debug = true;
    } else if ($argv[$i] == '-h') {
        usage();
    } else if ($argv[$i] == '-s') {
        if (!isset($argv[$i+1])) {
            echo "Error: Missing AS-SET-NAME\n";
            exit;
        } else if (!Radb::is_as_set($argv[$i+1])) {
            echo "Error: Invalid AS-SET-NAME\n";
            exit;
        } else {
            $query_as_sets[] = $argv[$i+1];
        }
        ++$i;
    } else if ($argv[$i] == '-n') {
        if (!isset($argv[$i+1])) {
            echo "Error: Missing AS-NUMBER\n";
            exit;
        } else if (!Radb::is_asn($argv[$i+1])) {
            echo "Error: Invalid AS-NUMBER\n";
            exit;
        } else {
            $query_asns[] = $argv[$i+1];
        }
        ++$i;
    } else if ($argv[$i] == '-o' || $argv[$i] == '-O') {
        if (!isset($argv[$i+1])) {
            echo "Error: Missing output file\n";
            exit;
        } else if (is_dir($argv[$i+1]) || (is_file($argv[$i+1]) && !is_writable($argv[$i+1]))) {
            echo "Error: Output file not writable\n";
            exit;
        } else {
            $output_file = $argv[$i+1];

            if ($argv[$i] == '-O') {
                $overwrite = true;
            }
        }
        ++$i;
    }
}

if (empty($query_asns) && empty($query_as_sets)) {
    usage();
}
if ($enable_debug) {
    define('RADB_DEBUG', true);
}

$ips = [];

foreach ($query_as_sets as $as_set) {
    debug_log("\e[33mQuery AS-SET: \e[32m{$as_set}\e[0m\n");
    Radb::query_as_set($as_set, $ips);
}

foreach ($query_asns as $asn) {
    debug_log("\e[33mQuery AS-Number: \e[32m{$asn}\e[0m\n");
    Radb::query_asn($asn, $ips);
}

if (empty($ips['route'])) {
    echo "NO IP Found\n";
    exit;
}

ksort($ips['route']);
$route4 = array_keys($ips['route']);

require(__DIR__ . '/ip_calc/autoload.php');

use sskaje\ip\Calculator;
use sskaje\ip\Merge;


$merge = new Merge();

foreach ($route4 as $r) {
    $merge->addIPCIDR($r);
    debug_log("\e[33mAdd Subnet\e[0m: \e[36m{$r}\e[0m\n");
}

$s = $merge->getBlocks();
debug_log("\e[33mMerge & Format Results\e[0m\n");

foreach ($s as $from=>$to) {
    debug_log("\e[33mMerge\e[0m: \e[37m{$from}\e[0m => \e[37m{$to}\e[0m\n");

    $s = Calculator::Range2Blocks($from, $to);
    foreach ($s as $ip) {
        list($subnet, $broadcast, $netmask, ) = Calculator::ipCidr2Subnet($ip['subnet'], $ip['cidr']);

        debug_log("\e[33mResult\e[0m: \e[37m{$subnet}\e[0m/\e[37m{$netmask}\e[0m BROADCAST:\e[37m{$broadcast}\e[0m\n");
        output($subnet . '/' . $ip['cidr'] . "\n");
    }
}
class Radb
{
    static public function is_asn($name)
    {
        return preg_match('#^AS\d+$#i', $name);
    }

    static public function is_as_set($name)
    {
        return preg_match('#^AS-[A-Z0-9\-]+$#i', $name);
    }

    static protected $queried_set = array();

    static public function query_as_set($as_set, &$ips=[])
    {
        $as_set = strtoupper($as_set);
        if (isset(self::$queried_set[$as_set])) {
            return;
        }
        self::$queried_set[$as_set] = 1;

        $assets = self::query('-K -T as-set ' . $as_set);

        if (isset($assets['members'])) {
            foreach ($assets['members'] as $asn) {
                if (self::is_asn($asn)) {
                    debug_log("query_asn {$asn}");
                    self::query_asn($asn, $ips);
                } else {
                    debug_log("found set {$asn}");
                    self::query_as_set($asn, $ips);
                }
            }
        }
    }

    static protected $queried_asn = array();

    static public function query_asn($asn, &$ips=[])
    {
        $asn = strtoupper($asn);
        if (isset(self::$queried_asn[$asn])) {
            return;
        }
        self::$queried_asn[$asn] = 1;

        $r = self::query('-K -i origin ' . $asn);

        if (isset($r['route'])) {
            foreach ($r['route'] as $n) {
                debug_log("found route: {$n}");
                $ips['route'][$n] = 1;
            }
        }

        if (isset($r['route6'])) {
            foreach ($r['route6'] as $n) {
                debug_log("found route6: {$n}");
                $ips['route6'][$n] = 1;
            }
        }
    }

    static public function query($cmd)
    {
        $socket = stream_socket_client('tcp://whois.radb.net:43', $errno, $error, 3, STREAM_CLIENT_CONNECT);
        fwrite($socket, $cmd . "\n");
        $r = '';
        $ret = [];
        $last_key = '';
        debug_log("\e[31mSend command:\e[0m {$cmd}");
        while (is_resource($socket) && !feof($socket)) {
            $rl = fgets($socket);
            $r .= $rl;
            $rl = trim($rl);

            if (empty($rl)) {
                $last_key = '';
                continue;
            }

            if ($rl[0] == '%') {
                # stderr
                debug_log("Error: {$cmd}: \e[31m{$rl}\e[0m");
                continue;
            }

            if (strpos($rl, ':')) {
                list($key, $val) = explode(':', $rl, 2);
            } else {
                $key = $last_key;
                $val = $rl;
            }

            $ret[$key][] = trim($val);
            $last_key = $key;
        }

        fclose($socket);

        if (isset($ret['members'])) {
            $new_members = [];
            foreach ($ret['members'] as $k=>$v) {
                if (strpos($v, ',')) {
                    $new_members = array_merge($new_members, preg_split('#[,\s]#', $v, -1, PREG_SPLIT_NO_EMPTY));
                } else {
                    $new_members[] = $v;
                }
            }
            $ret['members'] = array_unique($new_members);
        }

        return $ret;
    }
}

function copyright()
{
    echo <<<COPYRIGHT
Query IPv4 Ranges from RADB.net

Author: sskaje (http://sskaje.me/)


COPYRIGHT;

}

function usage()
{
    copyright();

    echo <<<USAGE
Usage:
    php query-ips.php OPTIONS

    OPTIONS:
        -d          Turn on DEBUG
        -s NAME     Set AS-SET-NAME
        -d NUMBER   Set AS-NUMBER
        -o FILE     Append output to file
        -O FILE     Overwrite output to file

Example:
    php query-ips.php -s AS-GOOGLE -d
    php query-ips.php -n AS15169 -d
    php query-ips.php -s AS-GOOGLE -s AS-TWITTER -d
    php query-ips.php -s AS-TWITTER -n AS15169 -d
    php query-ips.php -n AS15169 -d -o as15169.txt
    php query-ips.php -n AS15169 -d -O as15169.txt


USAGE;
    exit;
}

function debug_log($msg)
{
    if (defined('RADB_DEBUG') && RADB_DEBUG) {
        fwrite(STDERR, rtrim($msg) . "\n");
    }
}

function output($out)
{
    echo $out;

    global $output_file, $overwrite, $overwrite_init;
    if ($output_file) {
        file_put_contents(
            $output_file,
            $out,
            (!$overwrite || $overwrite && $overwrite_init) ? FILE_APPEND : 0
        );

        if (!$overwrite_init) {
            $overwrite_init = true;
        }
    }
}

# EOF
