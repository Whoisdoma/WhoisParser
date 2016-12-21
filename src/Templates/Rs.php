<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Rs extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=owner:)/is', 
            2 => '/owner:(?>[\x20\t]*)(.*?)(?=dns:)/is', 
            3 => '/dns:(?>[\x20\t]*)(.*?)(?=administrative contact)/is', 
            4 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=technical contact)/is', 
            5 => '/technical contact:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/domain status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/registration date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/modification date:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name'), 
            2 => array('/owner:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address'), 
            3 => array('/dns:(?>[\x20\t]*)(.+)\. - .*$/im' => 'nameserver', 
                    '/dns:(?>[\x20\t]*).+\. - (.*)$/im' => 'ips'), 
            4 => array('/administrative contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address'), 
            5 => array('/technical contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain is not registered/i';

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
                $filteredAddress = array_map('trim', explode(',', trim($contactObject->address)));
                
                if (sizeof($filteredAddress) === 3) {
                    $contactObject->address = $filteredAddress[0];
                    $contactObject->city = $filteredAddress[1];
                    $contactObject->country = $filteredAddress[2];
                }
                
                $filteredAddress = array_map('trim', explode(',', trim($contactObject->name)));
                
                if (sizeof($filteredAddress) === 2) {
                    $contactObject->name = $filteredAddress[0];
                    $contactObject->organization = $filteredAddress[1];
                }
            }
        }
    }
}