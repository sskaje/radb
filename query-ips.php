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

if (isset($argv[2]) && $argv[2] == '-d') {
    define('RADB_DEBUG', true);
}

$ips = [];

$name = $argv[1];
if (is_as_set($name)) {
    debug_log("\e[33mQuery AS-SET: \e[32m{$name}\e[0m\n");
    query_as_set($name, $ips);
} else if (is_asn($name)) {
    debug_log("\e[33mQuery AS-Number: \e[32m{$name}\e[0m\n");
    query_asn($name, $ips);

} else {
    usage();
}

ksort($ips['route']);
$route4 = array_keys($ips['route']);

require(__DIR__ . '/ip_calc/ipcalc.class.php');
require(__DIR__ . '/ip_calc/ip_merger.class.php');

$ipmerger = new IPMerger();

foreach ($route4 as $r) {
    $ipmerger->addBySubnet($r);
    debug_log("\e[33mAdd Subnet\e[0m: \e[36m{$r}\e[0m\n");
}

$s = $ipmerger->getSubnets();
debug_log("\e[33mMerge & Format Results\e[0m\n");

foreach ($s as $r) {
    debug_log("\e[33mMerge\e[0m: \e[37m{$r[IPMerger::BEGIN]}\e[0m => \e[37m{$r[IPMerger::END]}\e[0m\n");

    $s = IPCalculator::getSubnetsFromRange($r[IPMerger::BEGIN], $r[IPMerger::END]);
    foreach ($s as $ip) {
        list($subnet, $broadcast, $netmask) = IPCalculator::ipCidr2Subnet($ip['subnet'], $ip['cidr']);

        debug_log("\e[33mResult\e[0m: \e[37m{$subnet}\e[0m/\e[37m{$netmask}\e[0m BROADCAST:\e[37m{$broadcast}\e[0m\n");
        echo $subnet . '/' . $ip['cidr'] . "\n";
    }
}

function is_asn($name)
{
    return preg_match('#^AS\d+$#', $name);
}

function is_as_set($name)
{
    return preg_match('#^AS-[A-Z0-9\-]+$#', $name);
}

function query_as_set($as_set, &$ips=[])
{
    $assets = query('-K -T as-set ' . $as_set);

    foreach ($assets['members'] as $asn) {
        if (is_asn($asn)) {
            query_asn($asn, $ips);
        } else {
            query_as_set($asn, $ips);
        }
    }
}

function query_asn($asn, &$ips=[])
{
    $r = query('-K -i origin ' . $asn);

    if (isset($r['route'])) {
        foreach ($r['route'] as $n) {
            $ips['route'][$n] = 1;
        }
    }

    if (isset($r['route6'])) {
        foreach ($r['route6'] as $n) {
            $ips['route6'][$n] = 1;
        }
    }
}

function query($cmd)
{
    $socket = stream_socket_client('tcp://whois.radb.net:43', $errno, $error, 3, STREAM_CLIENT_CONNECT);
    fwrite($socket, $cmd . "\n");
    $r = '';
    $ret = [];
    while (!feof($socket)) {
        $rl = fgets($socket);
        $r .= $rl;
        if (!strpos($rl, ':')) {
            if (trim($rl)) {
                # stderr
                debug_log("\e[31mError\e[0m: " . $cmd . ": " . $rl);
            }
            continue;
        }
        list($key, $val) = explode(':', $rl, 2);
        $ret[$key][] = trim($val);
    }

    fclose($socket);

    if (isset($ret['members'])) {
        foreach ($ret['members'] as $k=>$v) {
            if (strpos($v, ',')) {
                unset($ret['members'][$k]);
                $ret['members'] = array_merge($ret['members'], preg_split('#[,\s]#', $v, -1, PREG_SPLIT_NO_EMPTY));
            }
        }
    }

    return $ret;
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
    php query-ips.php AS-SET-NAME|AS-NUMBER [-d]

Example:
    php query-ips.php AS-GOOGLE -d
    php query-ips.php AS15169 -d


USAGE;
    exit;
}

function debug_log($msg)
{
    if (defined('RADB_DEBUG') && RADB_DEBUG) {
        fwrite(STDERR, rtrim($msg) . "\n");
    }
}

# EOF