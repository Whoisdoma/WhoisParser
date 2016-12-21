<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Ro extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registered on:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/domain status:(?>[\x20\t]*)(.+)$/im' => 'status'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No entries found for the selected/i';
}