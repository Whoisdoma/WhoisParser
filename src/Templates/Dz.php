<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Dz extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/contact administratif#(?>[\. ]*)(.*?)(?=contact technique)/is', 
            2 => '/contact technique#(?>[\. ]*)(.*?)(?=-----------|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:name', 
                    '/organisme administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/adresse contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:address', 
                    '/telephone contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/fax contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/mail contact administratif#(?>[\. ]*)(.+)$/im' => 'contacts:owner:email'), 
            2 => array('/contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:name', 
                    '/organisme technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/adresse contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:address', 
                    '/telephone contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/mail contact technique#(?>[\. ]*)(.+)$/im' => 'contacts:tech:email', 
                    '/registrar#(?>[\. ]*)(.+)$/im' => 'registrar:name', 
                    '/date de creation#(?>[\. ]*)(.+)$/im' => 'created'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/NO OBJECT FOUND/i';
}