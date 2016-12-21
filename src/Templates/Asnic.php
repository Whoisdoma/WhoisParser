<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Asnic extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Registered by:(?>[\x20\t]*)(.*?)(?=Nameservers:)/is', 
            2 => '/Nameservers:(?>[\x20\t]*)(.*?)(?=Access to ASNIC)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registered by:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name'), 
            2 => array('/Nameservers:(?>[\x20\t]*)(.+)$/is' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain Not Found/i';

    /**
     * After parsing ...
     *
     * Fix nameserver and IP addresses in WHOIS output
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $filteredNameserver = array();
        $filteredIps = array();
        
        if ($ResultSet->nameserver != '') {
            $explodedNameserver = array_map('trim', explode("\n", trim($ResultSet->nameserver)));
            
            foreach ($explodedNameserver as $line) {
                preg_match('/(.+) \((.+)\)$/im', $line, $matches);
                $filteredNameserver[] = $matches[1];
                $filteredIps[] = $matches[2];
            }
            
            $ResultSet->nameserver = $filteredNameserver;
            $ResultSet->ips = $filteredIps;
        }
    }
}