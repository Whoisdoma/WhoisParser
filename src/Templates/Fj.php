<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Fj extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Status:(?>[\x20\t]*)(.*?)(?=Registrant)/is', 
            2 => '/Registrant:\n(?>[\x20\t]*)(.*?)(?=Domain servers)/is', 
            3 => '/Domain servers:\n(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Status:(?>[\x20\t]*)(.+)/im' => 'status', 
                    '/Expires:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/Registrant:\n(?>[\x20\t]*)(.+)$/is' => 'contacts:owner:address'), 
            3 => array('/\n(?>[\x20\t]+)(.+) .+$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+).+ (.+)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/was not found/i';

    /**
     * After parsing do something
     *
     * Fix address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (isset($ResultSet->contacts->owner[0]->address)) {
            $filteredAddress = array_map('trim', explode("\n", trim($ResultSet->contacts->owner[0]->address)));
            
            $ResultSet->contacts->owner[0]->name = $filteredAddress[0];
            $ResultSet->contacts->owner[0]->address = $filteredAddress[1];
        }
    }
}