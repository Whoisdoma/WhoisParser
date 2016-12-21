<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Im extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/domain managers(?>[\x20\t]*)(.*?)(?=domain owners \/ registrant)/is', 
            2 => '/domain owners \/ registrant(?>[\x20\t]*)(.*?)(?=administrative contact)/is', 
            3 => '/administrative contact(?>[\x20\t]*)(.*?)(?=billing contact)/is', 
            4 => '/billing contact(?>[\x20\t]*)(.*?)(?=technical contact)/is', 
            5 => '/technical contact(?>[\x20\t]*)(.*?)(?=domain details)/is', 
            6 => '/domain details(?>[\x20\t]*)(.*?)(?=name server)/is', 
            7 => '/name server:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name'), 
            2 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/address\n(?>[\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            3 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/address\n(?>[\x20\t]*)(.+)$/is' => 'contacts:admin:address'), 
            4 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/address\n(?>[\x20\t]*)(.+)$/is' => 'contacts:billing:address'), 
            5 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/address\n(?>[\x20\t]*)(.+)$/is' => 'contacts:tech:address'), 
            6 => array('/expiry date:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            7 => array('/name server:(?>[\x20\t]*)(.+)\./im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/was not found/i';

    /**
     * After parsing ...
     *
     * Fix contact addresses
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                switch (sizeof($filteredAddress)) {
                    case 4:
                        $contactObject->address = $filteredAddress[0];
                        $contactObject->zipcode = $filteredAddress[1];
                        $contactObject->country = $filteredAddress[2];
                        break;
                    case 5:
                        $contactObject->address = $filteredAddress[0];
                        $contactObject->city = $filteredAddress[1];
                        $contactObject->zipcode = $filteredAddress[2];
                        $contactObject->country = $filteredAddress[3];
                        break;
                    case 6:
                        $contactObject->address = $filteredAddress[0];
                        $contactObject->city = $filteredAddress[1];
                        $contactObject->state = $filteredAddress[2];
                        $contactObject->zipcode = $filteredAddress[3];
                        $contactObject->country = $filteredAddress[4];
                        break;
                    case 7:
                        $contactObject->address = array($filteredAddress[0], $filteredAddress[1]);
                        $contactObject->city = $filteredAddress[2];
                        $contactObject->state = $filteredAddress[3];
                        $contactObject->zipcode = $filteredAddress[4];
                        $contactObject->country = $filteredAddress[5];
                        break;
                }
            }
        }
    }
}