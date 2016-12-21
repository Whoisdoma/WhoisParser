<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Fo extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=contact)/is', 
            2 => '/nserver:(?>[\x20\t]*)(.*?)$/is', 3 => '/contact:(?>[\x20\t]*)(.*?)(?=nserver)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expire:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech'), 
            3 => array('/contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/org:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/street:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/created:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:created'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found./i';
}