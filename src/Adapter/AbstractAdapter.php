<?php

namespace Whoisdoma\WhoisParser\Adapter;


abstract class AbstractAdapter
{

    /**
     * Is successfully connected to the whois server?
     *
     * @var boolean
     * @access protected
     */
    protected $connected = false;

    /**
     * Resource handler for whois server
     *
     * @var resource
     * @access protected
     */
    protected $sock = false;

    protected $proxyConfig = null;


    public function __construct($proxyConfig)
    {
        $this->proxyConfig = $proxyConfig;
    }

    /**
     * Send data to whois server
     * 
     * @param  object $query
     * @param  array $config
     * @return string
     */
    abstract public function call($query, $config);

    /**
     * Creates an adapter by type
     * 
     * Returns a adapter object, if not null.
     * Socket or HTTP, default is socket.
     * 
     * @param  string $type
     * @param string|null $proxyConfig
     * @param string|null $customNamespace
     * @return AbstractAdapter
     */
    public static function factory($type = 'socket', $proxyConfig = null, $customNamespace = null)
    {
        $obj = null;
        // Ensure the custom namespace ends with a \
        $customNamespace = rtrim($customNamespace, '\\') .'\\';
        if ((strpos($type, '\\') !== false) && class_exists($type)) {
            $obj = new $type($proxyConfig);
        } elseif ((strlen($customNamespace) > 1) && class_exists($customNamespace . ucfirst($type))) {
            $class = $customNamespace . ucfirst($type);
            $obj = new $class($proxyConfig);
        } elseif (class_exists('Whoisdoma\WhoisParser\Adapter\\'. ucfirst($type))) {
            $class = 'Whoisdoma\WhoisParser\Adapter\\' . ucfirst($type);
            $obj = new $class($proxyConfig);
        }
        return $obj;
    }
}