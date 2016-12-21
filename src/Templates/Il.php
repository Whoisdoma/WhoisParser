<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Il extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/query:(?>[\x20\t]*)(.*?)(?=changed)/is', 
            2 => '/person:(?>[\x20\t]*)(.*?)(?=person:|registrar name:)/is', 
            3 => '/registrar name:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/descr:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/zone-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:zone', 
                    '/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/validity:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax'), 
            3 => array('/registrar name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/registrar info:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No data was found to match/i';

    /**
     * After parsing do something
     *
     * Fix contact address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $contactObject->email = str_replace(' AT ', '@', $contactObject->email);
                
                if (is_array($contactObject->address) && sizeof($contactObject->address) === 5) {
                    $contactObject->organization = $contactObject->address[0];
                    $contactObject->country = $contactObject->address[4];
                    $contactObject->city = $contactObject->address[2];
                    $contactObject->zipcode = $contactObject->address[3];
                    $contactObject->address = $contactObject->address[1];
                }
            }
        }
    }
}