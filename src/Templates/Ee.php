<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Ee extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(.*?)(?=expire)/is', 2 => '/nsset:(.*?)(?=created)/is', 
            3 => '/contact:(.*?)(?=created)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expire:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/registrant:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner', 
                    '/admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin'), 
            
            2 => array('/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech'), 
            
            3 => array('/contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/org:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found/i';
}