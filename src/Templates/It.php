<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class It extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=registrant)/is', 
            2 => '/registrant(?>[\x20\t]*)(.*?)(?=admin contact)/is', 
            3 => '/admin contact(?>[\x20\t]*)(.*?)(?=technical contacts)/is', 
            4 => '/technical contacts(?>[\x20\t]*)(.*?)(?=registrar)/is', 
            5 => '/registrar(?>[\x20\t]*)(.*?)(?=nameservers)/is', 
            6 => '/nameservers(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/last update:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expire date:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/contactid:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/address:(?>[\x20\t]*)(.+)(?=created)/is' => 'contacts:owner:address', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:created', 
                    '/last update:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:changed'), 
            3 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/contactid:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/address:(?>[\x20\t]*)(.+)(?=created)/is' => 'contacts:admin:address', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:created', 
                    '/last update:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:changed'), 
            4 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/contactid:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/address:(?>[\x20\t]*)(.+)(?=created)/is' => 'contacts:tech:address', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:created', 
                    '/last update:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:changed'), 
            5 => array('/organization:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'registrar:id'), 
            6 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/status:(?>[\x20\t]*)available/i';

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
                $filteredAddress = array_pad($filteredAddress, 5, '');
                $contactObject->address = $filteredAddress[0];
                $contactObject->city = $filteredAddress[1];
                $contactObject->zipcode = $filteredAddress[2];
                $contactObject->state = $filteredAddress[3];
                $contactObject->country = $filteredAddress[4];
            }
        }
    }
}
