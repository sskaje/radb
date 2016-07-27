<?php
$url = 'https://ip-ranges.amazonaws.com/ip-ranges.json';
$s = json_decode(file_get_contents($url), true);
foreach ($s['prefixes'] as $bl) {
    if ($bl['service'] === 'CLOUDFRONT') {
        echo $bl['ip_prefix'], "\n";
    }
}