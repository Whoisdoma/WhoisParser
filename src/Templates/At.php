<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class At extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=personname)/is', 
            2 => '/personname:(?>[\x20\t]*)(.*?)(?=personname:|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/remarks:(?>[\x20\t]*)(.+)$/im' => 'ips', 
                    '/_mnt-by:(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/registrant:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            
            2 => array('/nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/personname:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/street address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed', 
                    '/_status:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/_mnt-by:(?>[\x20\t]*)(.+)$/im' => 'contacts:maintaner'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/% nothing found/i';

    /**
     * After parsing ...
     *
     * If dnssec key was found we set attribute to true.
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec === 'Signed') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
    }
}