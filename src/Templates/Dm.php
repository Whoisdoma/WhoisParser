<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Dm extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=owner-contact)/is', 
            2 => '/owner-contact:(?>[\x20\t]*)(.*?)(?=admin-contact)/is', 
            3 => '/admin-contact:(?>[\x20\t]*)(.*?)(?=tech-contact)/is', 
            4 => '/tech-contact:(?>[\x20\t]*)(.*?)(?=billing-contact)/is', 
            5 => '/billing-contact:(?>[\x20\t]*)(.*?)(?=nameserver)/is', 
            6 => '/nameserver:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/registrar:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/url:(?>[\x20\t]*)(.+)$/im' => 'registrar:url', 
                    '/status:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/created date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/updated date:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/owner-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country'), 
            2 => array('/owner-contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/owner-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/owner-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/owner-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/owner-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/owner-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/owner-zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/owner-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/owner-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/owner-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/owner-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array('/admin-contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/admin-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/admin-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/admin-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/admin-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:city', 
                    '/admin-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/admin-zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/admin-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/admin-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/admin-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/admin-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array('/tech-contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/tech-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/tech-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/tech-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/tech-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/tech-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/tech-zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/tech-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/tech-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/tech-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/tech-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            5 => array('/billing-contact:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:handle', 
                    '/billing-organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/billing-name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/billing-street:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/billing-city:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:city', 
                    '/billing-state:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/billing-zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/billing-country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/billing-phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/billing-fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/billing-email:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            6 => array('/nameserver:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/not found.../i';
}