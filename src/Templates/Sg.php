<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Sg extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/registrar:(?>[\x20\t]*)(.*?)(?=registrant)/is', 
            2 => '/registrant:(?>[\x20\t]*)(.*?)(?=administrative contact)/is', 
            3 => '/administrative contact:(?>[\x20\t]*)(.*?)(?=technical contact)/is', 
            4 => '/technical contact:(?>[\x20\t]*)(.*?)(?=name servers)/is', 
            5 => '/name servers:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/creation date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/modified date:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/domain status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:owner:name', 
                    '/name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:owner:handle'), 
            3 => array('/name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:admin:name', 
                    '/name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:admin:handle'), 
            4 => array('/name:(?>[\x20\t]*)(.+) \(.+\)/im' => 'contacts:tech:name', 
                    '/name:(?>[\x20\t]*).+ \((.+)\)/im' => 'contacts:tech:handle', 
                    '/email:(?>[\x20\t]*)(.+)/im' => 'contacts:tech:email'), 
            5 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Domain Not Found/i';
}