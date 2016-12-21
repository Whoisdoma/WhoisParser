<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Bg extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registrant:)/is', 
            2 => '/registrant:(?>[\x20\t]*)(.*?)(?=administrative contact:)/is', 
            3 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=technical contact)/is', 
            4 => '/technical contact\(s\):(?>[\x20\t]*)(.*?)(?=name server information)/is',
            5 => '/name server information:(?>[\x20\t]*)(.*?)(?=dnssec)/is',
            6 => '/dnssec:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/processed from:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/expires at:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/registration status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/registrant:\n(?>[\x20\t]*)(.+)/is' => 'contacts:owner:address'), 
            3 => array(
                    '/administrative contact:\n(?>[\x20\t]*)(.+)(?=tel:)/is' => 'contacts:admin:address', 
                    '/tel:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/nic handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle'), 
            4 => array(
                    '/technical contact\(s\):\n(?>[\x20\t]*)(.+)(?=tel:)/is' => 'contacts:tech:address', 
                    '/tel:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/nic handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle'), 
            5 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]*)(.+) .+$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]*).+ \((.+)\)$/im' => 'ips'), 
            6 => array('/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/does not exist in database/i';

    /**
     * After parsing ...
     *
     * If dnssec key was found we set attribute to true. Furthermore we need
     * to fix the addresses of the contact handles because they are not well
     * formed.
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec === 'Active') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", $contactObject->address));
                $size = sizeof($filteredAddress);
                
                if ($size === 6) {
                    $contactObject->organization = $filteredAddress[0];
                    $contactObject->address = $filteredAddress[1];
                    $contactObject->city = $filteredAddress[2];
                    $contactObject->country = $filteredAddress[3];
                }
                
                if ($size === 7) {
                    $contactObject->name = $filteredAddress[0];
                    $contactObject->email = $filteredAddress[1];
                    $contactObject->organization = $filteredAddress[2];
                    $contactObject->address = $filteredAddress[3];
                    $contactObject->city = $filteredAddress[4];
                    $contactObject->country = $filteredAddress[5];
                }
                
                if ($size === 8) {
                    $contactObject->name = $filteredAddress[1];
                    $contactObject->email = $filteredAddress[2];
                    $contactObject->organization = $filteredAddress[3];
                    $contactObject->address = $filteredAddress[4];
                    $contactObject->city = $filteredAddress[5];
                    $contactObject->country = $filteredAddress[6];
                }
            }
        }
    }
}