<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\AbstractTemplate;
use Whoisdoma\WhoisParser\Templates\Type\Proxy;


class Gandi extends Proxy
{
    protected $template = null;

    protected $rateLimit = '/^\s*\# Your IP has been restricted due to excessive access, please wait a bit\s*$/im';

    protected $available = array(
        '/^\s*# Not found\s*/im',
    );

    /**
     * @param \Whoisdoma\WhoisParser\Result\Result $result
     * @param $rawdata
     * @param string|object $query
     */
    public function parse($result, $rawdata, $query)
    {
        $this->loadTemplate($rawdata);
        $this->parseRateLimit($rawdata);

        $this->template->parse($result, $rawdata, $query);
    }

    public function translateRawData($rawdata, $config)
    {
        $this->loadTemplate($rawdata);
        return $this->template->translateRawData($rawdata, $config);
    }

    protected function loadTemplate($rawdata)
    {
        if (is_object($this->template)) {
            return;
        }

        if (preg_match('/^\s*--- \#YAML/im', $rawdata)) {
            // YAML based output - eg. .cc
            $this->template = AbstractTemplate::factory('gandiyaml');
        } else {
            $this->template = AbstractTemplate::factory('standard');
        }
    }
}
