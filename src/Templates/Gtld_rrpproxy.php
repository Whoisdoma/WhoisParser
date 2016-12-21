<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Gtld_rrpproxy extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/owner-(id|contact|name|organization):(?>[\x20\t]*)(.*?)(?=admin-(id|contact|name|organization))/is', 
            2 => '/admin-(id|contact|name|organization):(?>[\x20\t]*)(.*?)(?=tech-(id|contact|name|organization))/is', 
            3 => '/tech-(id|contact|name|organization):(?>[\x20\t]*)(.*?)(?=billing-(id|contact|name|organization))/is', 
            4 => '/billing-(id|contact|name|organization):(?>[\x20\t]*)(.*?)(?=nameserver|$)/is', 
            5 => '/(nameserver|nserver)([0-9]{0,1}):(?>[\x20\t]*)(.*?)(?=owner-(id|contact|name|organization)|$)/is', 
            6 => '/created(\-| )date:(?>[\x20\t]*)(.*?)(?=owner-(id|contact|name|organization)|$)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^owner-(contact|id):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^owner-(organization|company|org):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^owner-([fl]{0,1})name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^owner-(street|address):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^owner-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^owner-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^owner-(zip|postcode|pcode):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^owner-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^owner-(telephone|phone):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^owner-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^owner-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            2 => array('/^admin-(contact|id):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/^admin-(organization|company|org):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^admin-([fl]{0,1})name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^admin-(street|address):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^admin-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^admin-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/^admin-(zip|postcode|pcode):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^admin-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^admin-(telephone|phone):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^admin-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^admin-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            3 => array('/^tech-(contact|id):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^tech-(organization|company|org):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^tech-([fl]{0,1})name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^tech-(street|address):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^tech-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^tech-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/^tech-(zip|postcode|pcode):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^tech-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^tech-(telephone|phone):(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^tech-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^tech-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            4 => array('/^billing-(contact|id):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle', 
                    '/^billing-(organization|company|org):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/^billing-([fl]{0,1})name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/^billing-(street|address):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/^billing-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/^billing-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/^billing-(zip|postcode|pcode):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/^billing-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/^billing-(telephone|phone):(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/^billing-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/^billing-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            5 => array('/^(nameserver|nserver)[0-9]{0,1}:(?>[\x20\t]*)(.*?)$/im' => 'nameserver'), 
            6 => array('/^created(\-| )date:(?>[\x20\t]*)(.*?)$/im' => 'created', 
                    '/^updated(\-| )date:(?>[\x20\t]*)(.*?)$/im' => 'changed', 
                    '/^(registration-){0,1}expiration(\-| )date:(?>[\x20\t]*)(.*?)$/im' => 'expires'));
}