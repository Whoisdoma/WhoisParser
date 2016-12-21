<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

/**
 * Template for .AM
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Am extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain name:(?>[\x20\t]*)(.*?)(?=Registrant\:)/is', 
            2 => '/Registrant:(?>[\x20\t]*)(.*?)(?=Administrative contact)/is', 
            3 => '/Administrative contact:(?>[\x20\t]*)(.*?)(?=Technical contact)/is', 
            4 => '/Technical contact:(?>[\x20\t]*)(.*?)(?=DNS servers|No name servers)/is', 
            5 => '/DNS servers:(?>[\x20\t]*)(.*?)(?=Registered)/is', 
            6 => '/Registered:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrar:(?>[\x20\t]*)(.*?)$/im' => 'registrar:name', 
                    '/Status:(?>[\x20\t]*)(.*?)$/im' => 'status'), 
            2 => array('/Registrant:\n(?>[\x20\t]*)(.*?)$/is' => 'contacts:owner:address'), 
            3 => array(
                    '/Administrative contact:\n(?>[\x20\t]*)(.*?)$/is' => 'contacts:admin:address'), 
            4 => array('/Technical Contact:\n(?>[\x20\t]*)(.*?)$/is' => 'contacts:tech:address'), 
            5 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver'), 
            6 => array('/Registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Last modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/Expires:(?>[\x20\t]*)(.+)$/im' => 'expires'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match/i';

    /**
     * After parsing do something
     *
     * Fix contact addresses
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
                $contactObject->address = array_map('trim', explode("\n", trim($contactObject->address)));
                
                if ($contactType === 'owner') {
                    $contactObject->organization = $contactObject->address[0];
                    
                    $explodedAddress = array_map('trim', explode(',', $contactObject->address[2]));
                    
                    if (sizeof($explodedAddress) === 2) {
                        $contactObject->city = $explodedAddress[0];
                        $contactObject->zipcode = $explodedAddress[1];
                    } else {
                        $contactObject->city = $explodedAddress[0];
                        $contactObject->state = $explodedAddress[1];
                        $contactObject->zipcode = $explodedAddress[2];
                    }
                    
                    $contactObject->country = $contactObject->address[3];
                    $contactObject->address = $contactObject->address[1];
                } else {
                    $contactObject->name = $contactObject->address[0];
                    $contactObject->organization = $contactObject->address[1];
                    $contactObject->country = $contactObject->address[4];
                    $contactObject->email = $contactObject->address[5];
                    $contactObject->phone = $contactObject->address[6];
                    $contactObject->fax = $contactObject->address[7];
                    
                    $explodedAddress = array_map('trim', explode(',', $contactObject->address[3]));
                    
                    if (sizeof($explodedAddress) === 2) {
                        $contactObject->city = $explodedAddress[0];
                        $contactObject->zipcode = $explodedAddress[1];
                    } else {
                        $contactObject->city = $explodedAddress[0];
                        $contactObject->state = $explodedAddress[1];
                        $contactObject->zipcode = $explodedAddress[2];
                    }
                    
                    $contactObject->address = $contactObject->address[2];
                }
            }
        }
    }
}