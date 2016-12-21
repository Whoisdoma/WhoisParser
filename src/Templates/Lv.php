<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Lv extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/\[Domain\](.*?)(?=\[Holder\])/is', 
            2 => '/\[Holder\](.*?)(?=\[Tech\])/is', 
            3 => '/\[Tech\](.*?)(?=\[Registrar|Nservers\])/is', 
            4 => '/\[Registrar\](.*?)(?=\[Nservers\])/is', 5 => '/\[Nservers\].*?$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            
            2 => array('/^name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^type:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:type', 
                    '/^email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/^fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address'), 
            
            3 => array('/^name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^type:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:type', 
                    '/^email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email', 
                    '/^fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address'), 
            
            4 => array('/^name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email'), 
            
            5 => array('/^Nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Status: free/i';
}