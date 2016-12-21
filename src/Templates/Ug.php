<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Ug extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain:(?>[\x20\t]*)(.*?)\n\n/is', 
            2 => '/\n\nAdmin Contact:(?>[\x20\t]*)(.*?)(?=Tech Contact:)/is', 
            3 => '/\n\nTech Contact:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registered:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Expiry:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/Status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/Nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/Updated:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/Admin Contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/NIC:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/City:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:admin:city', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone'), 
            3 => array('/Tech Contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/NIC:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/City:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:tech:city', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found for/i';
}