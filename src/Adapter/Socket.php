<?php

namespace Whoisdoma\WhoisParser\Adapter;

use Whoisdoma\WhoisParser\Exception\ConnectErrorException;
use Whoisdoma\WhoisParser\Exception\ReadErrorException;
use Whoisdoma\WhoisParser\Exception\WriteErrorException;


class Socket extends AbstractAdapter
{

    /**
     * ProxyList cache
     *
     * false if no proxy.ini found to skip check if file exists
     *
     * @var array|bool
     * @access protected
     */
    protected $proxyList = array();


    public function __construct($proxyConfig)
    {
        parent::__construct($proxyConfig);
    }


    /**
     * Send data to whois server
     *
     * @throws WriteErrorException
     * @throws ReadErrorException
     * @param  object $query
     * @param  array $config
     * @return string
     */
    public function call($query, $config)
    {
        $this->disconnect();
        $this->connect($config);

        usleep(1);
        stream_set_blocking($this->sock, 1);

        if  (is_object($query)) {
            if (isset($query->tld) && ! isset($query->idnFqdn)) {
                $lookupString = str_replace('%domain%', $query->tld, $config['format']);
            } elseif (isset($query->ip)) {
                $lookupString = str_replace('%domain%', $query->ip, $config['format']);
            } elseif (isset($query->asn)) {
                $lookupString = str_replace('%domain%', $query->asn, $config['format']);
            } else {
                $lookupString = str_replace('%domain%', $query->idnFqdn, $config['format']);
            }
        } else {
            $lookupString = str_replace('%domain%', $query, $config['format']);
        }

        $send = fwrite($this->sock, $lookupString . "\r\n");

        if ($send !== strlen($lookupString . "\r\n")) {
            throw new WriteErrorException(
                'Error while sending data (' . $send . '/' . strlen($lookupString . "\r\n") . ')'
            );
        }

        $read = $write = array($this->sock);
        $except = null;
        $rawdata = '';

        do {
            if (stream_select($read, $write, $except, 30) === false) {
                break;
            }

            $recv = stream_get_contents($this->sock);

            if ($recv === false) {
                throw new ReadErrorException('Could not read from socket.');
            }

            $rawdata .= $recv;
        } while ((! feof($this->sock)));

        // remove prepended response of proxy server
        if (is_array($this->proxyList)) {
            $rawdata = preg_replace('/^HTTP\/1\.1 200.+\n/', '', $rawdata);
        }

        // Servers have been seen returning no data.
        // This possibly happens when we're being rate limited, but it's not really possible to give any certain reason
        if (strlen($rawdata) < 1) {
            throw new ReadErrorException('No data read from server: '. $config['server']);
        }

        return str_replace("\r", '', $rawdata);
    }

    /**
     * Creates and initiates a socket connection
     *
     * @throws ConnectErrorException
     * @param  array $config
     * @return void
     */
    private function connect($config)
    {
        $parsed_socket = parse_url('tcp://' . $config['server']);

        if (isset($parsed_socket['port'])) {
            $config['port'] = $parsed_socket['port'];
        }

        if ($this->proxyList !== false) {
            $this->proxyList = $this->getProxyList();
        }

        if (is_array($this->proxyList)) {
            $proxyConfig = $this->getRandomProxy();
            $this->sock = $this->connectToProxy($proxyConfig, $config);
        }
        else {
            $errno = $errstr = null;
            $this->sock = @stream_socket_client('tcp://' . $config['server'] . ':' . $config['port'], $errno, $errstr, 30);
        }

        if (! is_resource($this->sock)) {
            throw new ConnectErrorException(
                'Unable to connect to ' . $config['server'] . ':' . $config['port'] . ' or missing configuration for this template.'
            );
        }

        $this->connected = true;
    }

    /**
     * Disconnect a socket connection
     *
     * @return boolean
     */
    private function disconnect()
    {
        if ($this->connected) {
            return @stream_socket_shutdown($this->sock, STREAM_SHUT_RDWR);
        }

        return true;
    }

    /**
     * Connects to proxy
     *
     * @throws WriteErrorException
     * @throws ConnectErrorException
     * @param  array $proxyConfig
     * @param  array $config
     * @return resource
     */
    private function connectToProxy(array $proxyConfig, array $config)
    {
        $proxyHost = $proxyConfig['host'] . ':' . $proxyConfig['port'];
        $proxyScheme = '';
        if ($proxyConfig['type'] == 'http') {
            $proxyScheme = 'tcp://';
        } elseif ($proxyConfig['type'] == 'https') {
            if (! extension_loaded('openssl')) {
                throw new ConnectErrorException('OpenSSL extension must be enabled to use a proxy over https');
            }
            $proxyScheme = 'ssl://';
        } else {
            throw new ConnectErrorException('Unknown proxy type:' . $proxyConfig['type']);
        }

        $socket = @stream_socket_client($proxyScheme . $proxyHost, $errno, $errstr, 30);

        if (! is_resource($socket)) {
            throw new ConnectErrorException('Unable to connect to proxy ' . $proxyScheme . $proxyHost);
        }

        $parsed_socket = parse_url('tcp://' . $config['server']);

        if (isset($parsed_socket['port'])) {
            $config['port'] = $parsed_socket['port'];
        }

        $request = array();
        $request[] = 'CONNECT ' . $config['server'] . ':' . $config['port'] . ' HTTP/1.1';
        $request[] = 'Host: ' . $proxyConfig['host'];
        $request[] = 'Proxy-Connection: keep-alive';

        if (! empty($proxyConfig['username']) && ! empty($proxyConfig['password'])) {
            $auth = $proxyConfig['username'] . ':' . $proxyConfig['password'];
            $auth = base64_encode($auth);
            $request[] = 'Proxy-Authorization: Basic ' . $auth;
        }

        $request_str = implode("\r\n", $request) . "\r\n\r\n";
        $send = fwrite($socket, $request_str);

        if ($send !== strlen($request_str)) {
            throw new WriteErrorException(
                'Error while sending data via proxy - send ' . $send . ' of ' . strlen($request_str) . ')'
            );
        }

        return $socket;
    }

    /**
     * Returns configuration for proxy if it's set, and false if it isn't set
     *
     * @return array|false Returns an associative array on success, and FALSE on failure.
     */
    private function getProxyList()
    {
        if (!strlen($this->proxyConfig)) {
            return false;
        }

        if (@is_readable($this->proxyConfig)) {
            $proxyList = parse_ini_file($this->proxyConfig, true);
            if (!empty($proxyList)) {
                return $proxyList;
            }
        }

        return false;
    }

    /**
     * Returns random configuration for proxy, and false if there is no valid configuration
     *
     * @throws ConnectErrorException
     * @return array Returns an associative array on success
     */
    private function getRandomProxy() {
        $i = count($this->proxyList);

        // check if random configuration is valid, and repeat if it's not
        while ($i--) {
            $randKey = array_rand($this->proxyList);
            $proxyConfig = $this->proxyList[$randKey];

            // return configuration only if basic options are set
            if (isset($proxyConfig['enabled']) && $proxyConfig['enabled'] == 1 && ! empty($proxyConfig['port'])
                && ! empty($proxyConfig['host']) && ! empty($proxyConfig['type'])) {
                    return $proxyConfig;
            }

            unset($this->proxyList[$randKey]);
        }

        throw new ConnectErrorException('No valid proxy found');
    }
}
