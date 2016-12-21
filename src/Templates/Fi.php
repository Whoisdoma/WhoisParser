<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Fi extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/status:(?>[\x20\t]*)(.*?)(?=more information is)/is', 
            2 => '/descr:(?>[\x20\t]*)(.*?)(?=status)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expires:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec', 
                    '/nserver:(?>[\x20\t]*)(.+) \[.+\]$/im' => 'nameserver'), 
            2 => array('/descr:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/domain not found/i';

    /**
     * After parsing ...
     *
     * If dnssec key was found we set attribute to true. Furthermore
     * we have to fix the owner address, because the WHOIS output is not
     * well formed.
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec !== 'no') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->organization = utf8_encode($contactObject->organization[0]);
                $contactObject->name = $contactObject->address[0];
                $contactObject->zipcode = $contactObject->address[2];
                $contactObject->city = $contactObject->address[3];
                $contactObject->address = $contactObject->address[1];
            }
        }
    }
}