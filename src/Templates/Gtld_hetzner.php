<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Gtld_hetzner extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/nameserver:(?>[\x20\t]*)(.*?)(?=registrant-name)/is', 
            2 => '/registrant-name:(?>[\x20\t]*)(.*?)(?=admin-c-name)/is', 
            3 => '/admin-c-name:(?>[\x20\t]*)(.*?)(?=tech-c-name)/is', 
            4 => '/tech-c-name:(?>[\x20\t]*)(.*?)(?=zone-c-name)/is', 
            5 => '/zone-c-name:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(1 => array('/^nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'), 
            2 => array(
                    '/^registrant-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^registrant-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^registrant-type:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:type', 
                    '/^registrant-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^registrant-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^registrant-postcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^registrant-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^registrant-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/^registrant-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/^registrant-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array(
                    '/^admin-c-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/^admin-c-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/^admin-c-type:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:type', 
                    '/^admin-c-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/^admin-c-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/^admin-c-postcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/^admin-c-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/^admin-c-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^admin-c-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^admin-c-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array(
                    '/^tech-c-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/^tech-c-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^tech-c-type:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:type', 
                    '/^tech-c-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/^tech-c-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/^tech-c-postcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/^tech-c-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/^tech-c-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^tech-c-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/^tech-c-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            5 => array(
                    '/^zone-c-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:organization', 
                    '/^zone-c-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:name', 
                    '/^zone-c-type:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:type', 
                    '/^zone-c-address:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:address', 
                    '/^zone-c-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:city', 
                    '/^zone-c-postcode:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:zipcode', 
                    '/^zone-c-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:country', 
                    '/^zone-c-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:phone', 
                    '/^zone-c-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:fax', 
                    '/^zone-c-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:zone:email'));
}