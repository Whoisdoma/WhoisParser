<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Ck extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=person|role)/is', 
            2 => '/(role|person):(?>[\x20\t]*)(.*?)(?=person|role|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/descr:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/remarks:(?>[\x20\t]*).+ (.+)$/im' => 'expires', 
                    '/changed:(?>[\x20\t]*).+ (.+)$/im' => 'changed', 
                    '/admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/billing-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:billing', 
                    '/zone-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:zone'), 
            
            2 => array('/nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/person:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/role:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/changed:(?>[\x20\t]*).+ (.+)$/im' => 'contacts:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/no entries found/i';

    /**
     * After parsing ...
     *
     * Fix contact addresses in WHOIS output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $size = sizeof($contactObject->address);
                
                if ($size === 3) {
                    $contactObject->city = $contactObject->address[1];
                    $contactObject->country = $contactObject->address[2];
                    $contactObject->address = $contactObject->address[0];
                }
                
                if ($size === 4) {
                    $contactObject->organization = $contactObject->address[0];
                    $contactObject->city = $contactObject->address[2];
                    $contactObject->country = $contactObject->address[3];
                    $contactObject->address = $contactObject->address[1];
                }
            }
        }
    }
}