<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Ie extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/descr:(?>[\x20\t]*)(.*?)(?=person)/is', 
            2 => '/person:(?>[\x20\t]*).*?[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^descr:(?>[\x20\t]*)(.+)\n/i' => 'contacts:owner:name', 
                    '/admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/registration:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/renewal:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            
            2 => array('/nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Not Registered/i';
}