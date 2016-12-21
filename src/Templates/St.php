<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class St extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=administrative contact)/is', 
            2 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=name servers)/is', 
            3 => '/name servers:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registrar:(?>[\x20\t]*)(.*?)$/im' => 'registrar:name', 
                    '/creation Date:(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/updated Date:(?>[\x20\t]*)(.*?)$/im' => 'changed', 
                    '/contact:(?>[\x20\t]*)(.*?)$/im' => 'registrar:email'), 
            2 => array('/owner:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:organization', 
                    '/^(?>[\x20\t]*)contact:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:name', 
                    '/address:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:address', 
                    '/city:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:city', 
                    '/country:(?>[\x20\t]*)(.*?)$/im' => 'contacts:admin:country'), 
            3 => array('/\n(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found/i';
}