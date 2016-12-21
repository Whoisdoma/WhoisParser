<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Mx extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Name:(?>[\x20\t]*)(.*?)(?=Registrant)/is', 
            2 => '/Registrant:(?>[\x20\t]*)(.*?)(?=Administrative Contact)/is', 
            3 => '/Administrative Contact:(?>[\x20\t]*)(.*?)(?=Technical Contact)/is', 
            4 => '/Technical Contact:(?>[\x20\t]*)(.*?)(?=Billing Contact)/is', 
            5 => '/Billing Contact:(?>[\x20\t]*)(.*?)(?=Name Servers)/is', 
            6 => '/Name Servers:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^Created On:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Expiration Date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/^Last Updated On:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/^URL:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'), 
            2 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/(?>[\x20\t]*)City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/(?>[\x20\t]*)State:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/(?>[\x20\t]*)Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country'), 
            3 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/(?>[\x20\t]*)City:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/(?>[\x20\t]*)State:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/(?>[\x20\t]*)Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country'), 
            4 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/(?>[\x20\t]*)City:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/(?>[\x20\t]*)State:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/(?>[\x20\t]*)Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country'), 
            5 => array('/(?>[\x20\t]*)Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/(?>[\x20\t]*)City:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/(?>[\x20\t]*)State:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/(?>[\x20\t]*)Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country'), 
            6 => array('/(?>[\x20\t]*)DNS:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Object_Not_Found/i';
}