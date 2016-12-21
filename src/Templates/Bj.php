<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Bj extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            2 => '/Person:(?>[\x20\t]*)(.*?)(?=To single out)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Last Updated:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Administrative Contact:(?>[\x20\t]*)(.+)$/im' => 'network:contact:admin', 
                    '/^Technical Contact:(?>[\x20\t]*)(.+)$/im' => 'network:contact:tech', 
                    '/^Name Server [0-9]*:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            2 => array('/^Name:(?>[\x20\t]*)(.+)$/im' => 'contact:name', 
                    '/^Email address:(?>[\x20\t]*)(.+)$/im' => 'contact:email', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contact:address', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contact:country', 
                    '/^Telephone:(?>[\x20\t]*)(.+)$/im' => 'contact:phone', 
                    '/^FAX No:(?>[\x20\t]*)(.+)$/im' => 'contact:fax', 
                    '/^Created:(?>[\x20\t]*)(.+)$/im' => 'contact:created', 
                    '/^Last Updated:(?>[\x20\t]*)(.+)$/im' => 'contact:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No records matching/i';

    /**
     * After parsing ...
     *
     * Get contact handles
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
    /**
        if (isset($ResultSet->network->contact->admin)) {
            $admin = trim($ResultSet->network->contact->admin);
            unset($ResultSet->network->contact->admin);
            $WhoisParser->call($admin);
            $ResultSet->contacts->admin = $ResultSet->contact;
        }
        
        if (isset($ResultSet->network->contact->tech)) {
            $tech = trim($ResultSet->network->contact->tech);
            unset($ResultSet->network->contact->tech);
            $WhoisParser->call($tech);
            $ResultSet->contacts->tech = $ResultSet->contact;
        }
        
        unset($ResultSet->contact);*/
    }
}