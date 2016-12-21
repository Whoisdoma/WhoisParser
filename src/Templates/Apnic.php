<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

/**
 * Template for APNIC
 *
 * @category   Novutec
 * @package    WhoisParser
 * @copyright  Copyright (c) 2007 - 2013 Novutec Inc. (http://www.novutec.com)
 * @license    http://www.apache.org/licenses/LICENSE-2.0
 */
class Apnic extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/(inetnum|inet6num):(?>[\x20\t]*)(.*?)source:(?>[\x20\t]*)apnic/is', 
            2 => '/(role|person|organisation):(?>[\x20\t]*)(.*?)source:(?>[\x20\t]*)apnic/is');

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
                    '/^admin-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:admin', 
                    '/^tech-c:(?>[\x20\t]*)(.+)$/im' => 'network:contacts:tech', 
                    '/^source:(?>[\x20\t]*)(.+)$/im' => 'network:source'), 
            
            2 => array('/^organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^org:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^nic-hdl:(?>[\x20\t]*)(.+)$/im' => 'contacts:handle', 
                    '/^org-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^role:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^person:(?>[\x20\t]*)(.+)$/im' => 'contacts:name', 
                    '/^address:(?>[\x20\t]*)(.+)/im' => 'contacts:address', 
                    '/^abuse-mailbox:(?>[\x20\t]*)(.+)$/im' => 'contacts:email', 
                    '/^phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:phone', 
                    '/^fax-no:(?>[\x20\t]*)(.+)$/im' => 'contacts:fax'));

    /**
     * After parsing do something
     * 
     * If APNIC says the organization is KRNIC then connect to KRNIC and
     * start over again.
     * 
	 * @param  object &$WhoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();
        
        if (isset($ResultSet->network->name) && $ResultSet->network->name === 'KRNIC-KR') {
            $ResultSet->reset();
            $Config->setCurrent($Config->get('krnic'));
            $WhoisParser->call();
        }
    }
}