<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Ax extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Name Server)/is', 
            2 => '/Name Server 1:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Administrative Contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Email address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/Telephone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/Created:(?>[\x20\t]*)(.+)$/im' => 'created'), 
            2 => array('/Name Server [0-9]:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No records matching/i';

    /**
     * After parsing ...
     *
     * Fix UTF-8
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredAddress = array();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->name = utf8_encode($contactObject->name);
                if (is_array($contactObject->address)) {
                    foreach ($contactObject->address as $elem) {
                        $filteredAddress[] = utf8_encode($elem);
                    }
                    $contactObject->address = $filteredAddress;
                } else {
                    $contactObject->address = utf8_encode($contactObject->address);
                }
            }
        }
    }
}