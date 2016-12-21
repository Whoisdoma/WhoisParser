<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Om extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Registrant Contact ID)/is', 
            2 => '/Registrant Contact ID:(?>[\x20\t]*)(.*?)(?=Tech Contact ID)/is', 
            3 => '/Tech Contact ID:(?>[\x20\t]*)(.*?)(?=Name Server)/is', 
            4 => '/Name Server:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Last Modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Registrar Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^Status:(?>[\x20\t]*)(.+)$/im' => 'status'), 
            2 => array('/^Registrant Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^Registrant Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Registrant Contact City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^Registrant Contact Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country'), 
            3 => array('/^Tech Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^Tech Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Tech Contact City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^Tech Contact Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country'), 
            4 => array('/^Name Server:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^Name Server IP:(?>[\x20\t]*)(.+)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Data Found/i';
}