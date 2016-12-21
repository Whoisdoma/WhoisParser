<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Qa extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registrant contact id)/is', 
            2 => '/registrant contact id:(?>[\x20\t]*)(.*?)(?=tech contact id)/is', 
            3 => '/tech contact id:(?>[\x20\t]*)(.*?)(?=name server)/is', 
            4 => '/name server:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/last modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/registrar name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/registrant contact id:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/registrant contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/registrant contact city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/registrant contact country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country'), 
            3 => array('/tech contact id:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/tech contact name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/tech contact city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/tech contact country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country'), 
            4 => array('/name server:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/name server ip:(?>[\x20\t]*)(.+)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Data Found/i';
}