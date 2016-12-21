<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Krnic extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/(\[ Network Information \])[\n]{1}(.*?)[\n]{2}/is', 
            2 => '/(\[ Admin Contact Information \])[\n]{1}(.*?)[\n]{2}/is', 
            3 => '/(\[ Tech Contact Information \])[\n]{1}(.*?)[\n]{2}/is', 
            4 => '/(\[ Network Abuse Contact Information \])[\n]{1}(.*?)[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^IPv4 Address[\s]*:[\s]*(.+)$/im' => 'network:inetnum', 
                    '/^IPv6 Address[\s]*:[\s]*(.+)$/im' => 'network:inetnum', 
                    '/^Service Name[\s]*:[\s]*(.+)$/im' => 'network:name', 
                    '/^Organization ID[\s]*:[\s]*(.+)$/im' => 'contacts:owner:handle', 
                    '/^Organization Name[\s]*:[\s]*(.+)$/im' => 'contacts:owner:name', 
                    '/^Address[\s]*:[\s]*(.+)$/im' => 'contacts:owner:address', 
                    '/^Zip Code[\s]*:[\s]*(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^Registration Date[\s]*:[\s]*(.+)$/im' => 'created'), 
            
            2 => array('/^Name[\s]*:[\s]*(.+)$/im' => 'contacts:admin:name', 
                    '/^Phone[\s]*:[\s]*(.+)$/im' => 'contacts:admin:phone', 
                    '/^E-Mail[\s]*:[\s]*(.+)$/im' => 'contacts:admin:email'), 
            
            3 => array('/^Name[\s]*:[\s]*(.+)$/im' => 'contacts:tech:name', 
                    '/^Phone[\s]*:[\s]*(.+)$/im' => 'contacts:tech:phone', 
                    '/^E-Mail[\s]*:[\s]*(.+)$/im' => 'contacts:tech:email'), 
            
            4 => array('/^Name[\s]*:[\s]*(.+)$/im' => 'contacts:abuse:name', 
                    '/^Phone[\s]*:[\s]*(.+)$/im' => 'contacts:abuse:phone', 
                    '/^E-Mail[\s]*:[\s]*(.+)$/im' => 'contacts:abuse:email'));
}