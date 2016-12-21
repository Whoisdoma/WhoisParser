<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Gtld_deutschetelekom extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=nic-hdl\:)/is', 
            2 => '/nic-hdl:(?>[\x20\t]*)(.*?)[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^registrant(-hdl)?:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner',
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^zone-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:zone', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^expires:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^type:(?>[\x20\t]*)(.+)$/im' => 'contacts:type', 
                    '/^title:(?>[\x20\t]*)(.+)$/im' => 'contacts:title', 
                    '/^name of the organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:organization', 
                    '/^(first|last)name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^address:(?>[\x20\t]*)(.+)$/im' => 'contacts:address', 
                    '/^city:(?>[\x20\t]*)(.+)$/im' => 'contacts:city', 
                    '/^state:(?>[\x20\t]*)(.+)$/im' => 'contacts:state', 
                    '/^pcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:zipcode', 
                    '/^country:(?>[\x20\t]*)(.+)$/im' => 'contacts:country', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));
}