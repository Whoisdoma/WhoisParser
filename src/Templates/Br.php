<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Br extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            2 => '/nic-hdl-br:(?>[\x20\t]*)(.*?)([\n]{2}|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^owner-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^billing-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:zone', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^expires:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/^nic-hdl-br:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'contacts:created', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(No match for domain|release process: reserved)/i';


    public function translateRawData($rawdata, $config)
    {
        return utf8_encode($rawdata);
    }
}