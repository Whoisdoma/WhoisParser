<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class De extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)[\n]{2}/is', 
            2 => '/\[(holder|zone|tech|admin)(\-c)?\]\n(.*?)([\n]{2}|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/dnskey:(?>[\x20\t]*)(.+)$/im' => 'dnssec', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/regaccname:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/regcccid:(?>[\x20\t]*)(.+)$/im' => 'registrar:id'), 
            
            2 => array('/\[(holder|zone|tech|admin)/i' => 'contacts:reservedType', 
                    '/type:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/countrycode:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/status:(?>[\x20\t]*)free/i';

    protected $rateLimit = '/^% Error: [0-9]+ Connection Refused; access control limit exceeded/im';

    /**
     * After parsing ...
     *
     * Move the attribute holder to owner and fix dnssec
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
        
        if (isset($ResultSet->contacts->holder)) {
            $ResultSet->contacts->owner = $ResultSet->contacts->holder;
            unset($ResultSet->contacts->holder);
        }
    }
}