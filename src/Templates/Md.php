<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Md extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain name:(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrant:(.*)$/im' => 'contacts:owner:name', 
                    '/Created: (.*)$/im' => 'created', '/Expiration date: (.*)$/im' => 'expires', 
                    '/Name server: (.*) .*$/im' => 'nameserver', 
                    '/Name server: .* (.*)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match for/i';
}