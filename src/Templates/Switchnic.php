<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

/**
 * Template for Switch Domains .CH / .LI
 *
 * @category   Whoisdoma
 * @package    WhoisParsers
 */
class Switchnic extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/holder of domain name:\n(.*?)(?=contractual language)/is', 
            2 => '/technical contact:\n(.*?)(?=dnssec)/is', 3 => '/dnssec:(.*?)(?=name servers)/is', 
            4 => '/name servers:\n(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/holder of domain name:\n(.*)$/is' => 'contacts:owner:address'), 
            2 => array('/technical contact:\n(.*?)$/is' => 'contacts:tech:address'), 
            3 => array('/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            4 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]*)(.+)(?>[\x20\t]*)\[.+\]$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]*).+(?>[\x20\t]*)\[(.+)\]$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/We do not have an entry in our database matching your query/i';

    /**
     * After parsing ...
     * 
     * Fix contact addresses and set dnssec
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec === 'Y') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        foreach ($ResultSet->contacts as $contactType => $contactArray) {
            foreach ($contactArray as $contactObject) {
                $filteredAddress = array_map('trim', explode("\n", trim($contactObject->address)));
                
                
                switch (sizeof($filteredAddress)) {
                    case 6:
                        $contactObject->organization = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->country = $filteredAddress[5];
                        $contactObject->city = $filteredAddress[4];
                        $contactObject->address = $filteredAddress[3];
                        break;
                    case 5:
                        $contactObject->organization = $filteredAddress[0];
                        $contactObject->name = $filteredAddress[1];
                        $contactObject->country = $filteredAddress[4];
                        $contactObject->city = $filteredAddress[3];
                        $contactObject->address = $filteredAddress[2];
                        break;
                    default:
                        //do nothing.
                }
            }
        }
    }
}
