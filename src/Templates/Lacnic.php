<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Lacnic extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/(inetnum|inet6num):[\s]*(.*?)[\n]{2}/is', 
            2 => '/nic-hdl:[\s]*(.*?)[\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^inetnum:(?>[\x20\t]*)(.+)$/im' => 'network:inetnum', 
                    '/^inet6num:(?>[\x20\t]*)(.+)$/im' => 'network:inetnum', 
                    '/^netname:(?>[\x20\t]*)(.+)$/im' => 'network:name', 
                    '/^mnt-by:(?>[\x20\t]*)(.+)$/im' => 'network:maintainer', 
                    '/^status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^nserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^abuse-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:abuse', 
                    '/^owner-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:owner'), 
            
            2 => array('/^organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^org:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^org-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^role:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^address:(?>[\x20\t]*)(.+)/im' => 'contacts:address', 
                    '/^abuse-mailbox:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^e-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'contacts:created', 
                    '/^changed:(?>[\x20\t]*)(.+)$/im' => 'contacts:changed'));
}