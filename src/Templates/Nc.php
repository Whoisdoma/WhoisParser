<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Nc extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain(?>[\x20\t]*):(.*?)(?=domain server)/is', 
            2 => '/domain server (.*?)(?=registrant name)/is', 
            3 => '/registrant name(?>[\x20\t]*):(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/created on(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/last updated on(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expires on(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/domain server [0-9]{1}(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            3 => array(
                    '/registrant name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/registrant address [0-9]{1}(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/contact (first|last)name(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found/i';

    /**
     * After parsing ...
     *
     * Fix owner contact address
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if (isset($ResultSet->contacts->owner[0]->address)) {
            if (sizeof($ResultSet->contacts->owner[0]->address) === 5) {
                $ResultSet->contacts->owner[0]->city = $ResultSet->contacts->owner[0]->address[3];
                $ResultSet->contacts->owner[0]->country = $ResultSet->contacts->owner[0]->address[4];
                $ResultSet->contacts->owner[0]->address = array(
                        $ResultSet->contacts->owner[0]->address[0], 
                        $ResultSet->contacts->owner[0]->address[1], 
                        $ResultSet->contacts->owner[0]->address[2]);
            } else {
                $ResultSet->contacts->owner[0]->city = $ResultSet->contacts->owner[0]->address[2];
                $ResultSet->contacts->owner[0]->address = array(
                        $ResultSet->contacts->owner[0]->address[0], 
                        $ResultSet->contacts->owner[0]->address[1]);
            }
        }
    }
}