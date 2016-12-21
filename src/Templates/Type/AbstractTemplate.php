<?php

namespace Whoisdoma\WhoisParser\Templates\Type;

use Whoisdoma\WhoisParser\Exception\RateLimitException;

abstract class AbstractTemplate
{

    /**
     * Blocks within the raw output of the whois
     *
     * @var array
     * @access protected
     */
    protected $blocks = array();

    /**
     * Items for each block
     *
     * @var array
     * @access protected
     */
    protected $blockItems = array();

    /**
     * Writing data to properties
     *
     * @param  string $name
     * @param  mixed $value
     * @return void
     */
    public function __set($name, $value)
    {
        $this->{$name} = $value;
    }

    /**
     * Checking data
     *
     * @param  mixed $name
     * @return boolean
     */
    public function __isset($name)
    {
        return isset($this->{$name});
    }

    /**
     * Reading data from properties
     *
     * @param  string $name
     * @return void
     */
    public function __get($name)
    {
        if (isset($this->{$name})) {
            return $this->{$name};
        }
        
        return null;
    }

    /**
     * Load Template
     * 
     * Returns a template object, if not null.
     *
     * @param  string $template
     * @return mixed
     */
    public static function factory($template, $customNamespace = null)
    {
        $template = ucfirst(str_replace('.', '_', $template));

        $obj = null;

        // Ensure the custom namespace ends with a \
        $customNamespace = rtrim($customNamespace, '\\') .'\\';
        if ((strpos($template, '\\') !== false) && class_exists($template, true)) {
            $class = $template;
            $obj = new $class();
        } elseif ((strlen($customNamespace) > 1) && class_exists($customNamespace . $template)) {
            $class = $customNamespace . $template;
            $obj = new $class();
        } elseif (class_exists('Whoisdoma\WhoisParser\Templates\\'. $template)) {
            $class = 'Whoisdoma\WhoisParser\Templates\\'. $template;
            $obj = new $class();
        }
        return $obj;
    }

    /**
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {}


    /**
     * @param \Whoisdoma\WhoisParser\Result\Result $previousResult
     * @param $rawdata
     * @param string|object $query
     * @throws \Whoisdoma\WhoisParser\Exception\ReadErrorException if data was read from the whois response
     */
    public abstract function parse($previousResult, $rawdata, $query);

    protected function parseRateLimit($rawdata)
    {
        if (isset ($this->rateLimit) && strlen($this->rateLimit)) {
            $count = preg_match_all($this->rateLimit, $rawdata, $matches);
            if ($count > 0) {
                throw new RateLimitException("Rate limit exceeded for server");
            }
        }
    }


    /**
     * Perform any necessary translation on the raw data before processing (for example, re-encoding to UTF-8)
     *
     * @param string $rawdata
     * @param array $config
     * @return string
     */
    public function translateRawData($rawdata, $config)
    {
        if (array_key_exists('encoding', $config)) {
            switch (strtolower($config['encoding'])) {
                case 'iso-8859-1':
                    $rawdata = utf8_encode($rawdata);
                    break;
            }
        }

        return $rawdata;
    }


    /**
     * Parse the raw data using the available regex list
     * @param string $rawdata
     * @param \Whoisdoma\WhoisParser\Result\Result $result
     * @return bool Parsed & matched?
     */
    protected function parseAvailable($rawdata, $result)
    {
        $parsedAvailable = false;
        if (isset($this->available)) {
            if ((!is_array($this->available)) && strlen($this->available)) {
                $this->available = array($this->available);
            }

            $isRegistered = true;
            if (is_array($this->available)) {
                foreach ($this->available as $availableRegex) {
                    $matches = array();
                    preg_match_all($availableRegex, $rawdata, $matches);

                    if (count($matches[0])) {
                        $parsedAvailable = true;
                        $isRegistered = false;
                    }
                }
            }

            $result->addItem('registered', $isRegistered);
        }

        return $parsedAvailable;
    }
}