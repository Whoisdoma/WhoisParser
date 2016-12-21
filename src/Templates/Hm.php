<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Hm extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Domain Registrant:(?>[\x20\t]*)(.*?)(?=Adminstrative Contact\:)/is', 
            2 => '/Adminstrative Contact:(?>[\x20\t]*)(.*?)(?=Technical Contact)/is', 
            3 => '/Technical Contact:(?>[\x20\t]*)(.*?)(?=Billing Contact)/is', 
            4 => '/Billing Contact:(?>[\x20\t]*)(.*?)(?=Name Server)/is', 
            5 => '/Name Server:(?>[\x20\t]*)(.*?)(?=Domain creation date)/is', 
            6 => '/Domain creation date:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Domain Registrant:(?>[\x20\t]*)(.*?)$/is' => 'contacts:owner:address'), 
            2 => array('/Adminstrative Contact:(?>[\x20\t]*)(.*?)$/is' => 'contacts:admin:address'), 
            3 => array('/Technical Contact:(?>[\x20\t]*)(.*?)$/is' => 'contacts:tech:address'), 
            4 => array('/Billing Contact:(?>[\x20\t]*)(.*?)$/is' => 'contacts:billing:address'), 
            5 => array('/Name Server:(?>[\x20\t]*)(.*?)$/im' => 'nameserver'), 
            6 => array('/Domain creation date:(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/Domain expiration date:(?>[\x20\t]*)(.*?)$/im' => 'expires'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain not found./i';

    /**
     * After parsing do something
     *
     * Fix address and nameservers
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
                if (! is_array($contactObject->address)) {
                    $explodedAddress = explode("\n", trim($contactObject->address));
                    
                    foreach ($explodedAddress as $key => $line) {
                        $filteredAddress[] = trim($line);
                    }
                    
                    if (sizeof($filteredAddress) === 4) {
                        $contactObject->name = $filteredAddress[0];
                        $contactObject->address = $filteredAddress[1];
                        $contactObject->city = $filteredAddress[2];
                        $contactObject->country = $filteredAddress[3];
                    } else {
                        preg_match('/([a-z0-9]+)\((.*)\)$/im', $filteredAddress[0], $matches);
                        
                        if (isset($matches[1])) {
                            $contactObject->handle = $matches[1];
                        }
                        
                        if (isset($matches[2])) {
                            $contactObject->email = $matches[2];
                        }
                        
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->organization = $filteredAddress[2];
                        $contactObject->address = $filteredAddress[3];
                        $contactObject->city = $filteredAddress[4];
                        $contactObject->country = $filteredAddress[5];
                        $contactObject->phone = trim(str_replace('Telephone: ', '', $filteredAddress[6]));
                        $contactObject->fax = trim(str_replace('Fax:', '', $filteredAddress[7]));
                    }
                    
                    $filteredAddress = array();
                }
            }
        }
    }
}