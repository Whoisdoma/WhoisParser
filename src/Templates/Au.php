<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Au extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Registrant:)/is', 
            2 => '/Registrant:(?>[\x20\t]*)(.*?)(?=Tech Contact ID:)/is', 
            3 => '/Tech Contact ID:(?>[\x20\t]*)(.*?)(?=Name Server)/is',
            4 => '/Name Server:(?>[\x20\t]*)(.*?)$/is',
            5 => '/DNSSEC:(?>[\x20\t]*)(.*?)$/is',
    );

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Registrar ID:(?>[\x20\t]*)(.+)$/im' => 'registrar:id', 
                    '/Registrar Name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/Status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/Last Modified:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/Registrant Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/Registrant Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Registrant:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/Eligibility Type:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:eligibility_type', 
                    '/Eligibility Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:eligibility_name', 
                    '/Eligibility ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:eligibility_id'), 
            3 => array('/Tech Contact ID:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/Tech Contact Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name'), 
            4 => array('/Name Server:(?>[\x20\t]*)(.+)$/im' => 'nameserver'),
            5 => array('/DNSSEC:(?>[\x20\t]*)(.+)$/im' => 'dnssec'),
    );

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No Data Found/i';
}