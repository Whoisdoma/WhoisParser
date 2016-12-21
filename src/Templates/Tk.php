<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

/**
 * Template for .TK, .CF
 *
 * @category   Whoisdoma
 * @package    WhoisParser
 */
class Tk extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/organisation:\n(.*?)(?=domain nameservers)/is', 
            2 => '/domain registered:(?>[\x20\t]*)(.*?)$/is', 
            3 => '/domain nameservers:\n(?>[\x20\t]*)(.*?)(?=domain registered)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/organisation:(.*?)$/is' => 'contacts:owner:address'), 
            2 => array('/domain registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/record will expire on:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            3 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+)(.+) \(.+\)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+).+ \((.+)\)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Invalid query or domain name not known in/i';

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
        
        if (isset($ResultSet->contacts->owner[0]->address)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->owner[0]->address)));
            $filteredAddress = array_pad($filteredAddress, 9, '');            
            $ResultSet->contacts->owner[0]->organization = $filteredAddress[0];
            $ResultSet->contacts->owner[0]->name = $filteredAddress[1];
            $ResultSet->contacts->owner[0]->city = $filteredAddress[3];
            $ResultSet->contacts->owner[0]->state = $filteredAddress[4];
            $ResultSet->contacts->owner[0]->country = $filteredAddress[5];
            $ResultSet->contacts->owner[0]->phone = str_replace('Phone: ', '', $filteredAddress[6]);
            $ResultSet->contacts->owner[0]->fax = str_replace('Fax: ', '', $filteredAddress[7]);
            $ResultSet->contacts->owner[0]->email = str_replace('E-mail: ', '', $filteredAddress[8]);
            $ResultSet->contacts->owner[0]->address = $filteredAddress[2];
        }
    }
}
