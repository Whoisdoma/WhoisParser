<?php

namespace Whoisdoma\WhoisParser\Adapter;


class Http extends AbstractAdapter
{

    public function __construct($proxyConfig)
    {
        parent::__construct($proxyConfig);
    }

    /**
     * Send data to whois server
     * 
     * @param  string $query
     * @param  array $config
     * @return string
     */
    public function call($query, $config)
    {
        $this->sock = curl_init();
        $replacements = array(
            '%domain%' => $query->idnFqdn,
            '%subdomain%' => $query->domain,
            '%tld%' => $query->tld,
        );
        $url = $config['server'] . str_replace(array_keys($replacements), array_values($replacements), $config['format']);
        
        curl_setopt($this->sock, CURLOPT_USERAGENT, 'PHP');
        curl_setopt($this->sock, CURLOPT_TIMEOUT, 30);
        curl_setopt($this->sock, CURLOPT_HEADER, false);
        curl_setopt($this->sock, CURLOPT_SSL_VERIFYPEER, 'OFF');
        curl_setopt($this->sock, CURLOPT_SSLVERSION, 3);
        curl_setopt($this->sock, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->sock, CURLOPT_POST, false);
        curl_setopt($this->sock, CURLOPT_URL, $url);
        
        $rawdata = curl_exec($this->sock);
        
        curl_close($this->sock);
        
        return $rawdata;
    }
}