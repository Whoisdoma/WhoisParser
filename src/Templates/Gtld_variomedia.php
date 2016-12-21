<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Gtld_variomedia extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/\[Registrant\](.*?)(?=\[Admin\])/is', 
            2 => '/\[Admin\](.*?)(?=\[Tech\])/is', 
            3 => '/\[Tech\](.*?)(?=\[Nameservers\])/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^(First|Last) name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Street[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^State:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^Postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            2 => array('/^Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^(First|Last) name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^Street[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^State:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^Postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'),  
            3 => array('/^Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^(First|Last) name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^Street[0-9]:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^State:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^Postal code:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^Email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'));
}