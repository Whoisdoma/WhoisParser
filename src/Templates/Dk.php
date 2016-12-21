<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Dk extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=registrant)/is', 
            2 => '/registrant\n(.*?)(?=administrator)/is', 
            3 => '/administrator\n(.*?)(?=nameservers)/is', 4 => '/nameservers\n(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/expires:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone'), 
            3 => array('/handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/postalcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone'), 
            4 => array('/hostname:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found for the selected source/i';
}