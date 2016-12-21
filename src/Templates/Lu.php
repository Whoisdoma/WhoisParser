<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Lu extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domainname:(?>[\x20\t]*)(.*?)(?=org-name:)/is', 
            2 => '/org-name:(?>[\x20\t]*)(.*?)(?=adm-name)/is', 
            3 => '/adm-name:(?>[\x20\t]*)(.*?)(?=tec-name)/is', 
            4 => '/tec-name:(?>[\x20\t]*)(.*?)(?=registrar-name)/is', 
            5 => '/registrar-name:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^domaintype:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/^org-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^org-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^org-zipcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^org-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^org-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^org-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array('/^adm-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^adm-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^adm-zipcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^adm-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^adm-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^adm-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array('/^tec-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^tec-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^tec-zipcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^tec-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^tec-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^tec-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            5 => array('/^registrar-name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^registrar-email:(?>[\x20\t]*)(.+)$/im' => 'registrar:email', 
                    '/^registrar-url:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No such domain/i';
}