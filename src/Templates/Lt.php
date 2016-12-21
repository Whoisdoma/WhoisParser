<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Lt extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain:(?>[\x20\t]*)(.*?)(?=Registrar:)/is', 
            2 => '/Registrar:(?>[\x20\t]*)(.*?)(?=Contact (name|organization))/is', 
            3 => '/Contact (name|organization):(?>[\x20\t]*)(.*?)(?=Contact (name|organization)|Nameserver)/is', 
            4 => '/Nameserver:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^Registered:(?>[\x20\t]*)(.+)$/im' => 'created'), 
            2 => array('/^Registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^Registrar website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/^Registrar email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email'), 
            3 => array('/^Contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Contact organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^Contact email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            4 => array('/^Nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Status:[\s]*available/i';
}