<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Pr extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Created On:(?>[\x20\t]*)(.*?)(?=(Contact:(?>[\x20\t]*)Organization|DNS:))/is', 
            2 => '/Contact:(?>[\x20\t]*)Organization(?>[\x20\t]*)(.*?)(?=Contact:(?>[\x20\t]*)Administrative)/is', 
            3 => '/Contact:(?>[\x20\t]*)Administrative(?>[\x20\t]*)(.*?)(?=Contact:(?>[\x20\t]*)Technical)/is', 
            4 => '/Contact:(?>[\x20\t]*)Technical(?>[\x20\t]*)(.*?)(?=Contact:(?>[\x20\t]*)Billing)/is', 
            5 => '/Contact:(?>[\x20\t]*)Billing(?>[\x20\t]*)(.*?)(?=DNS:)/is', 
            6 => '/DNS:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Created On:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/Expires On:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/City:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:owner:city', 
                    '/State:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/Zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax', 
                    '/E-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email'), 
            3 => array('/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:organization', 
                    '/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:name', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:address', 
                    '/City:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:admin:city', 
                    '/State:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:state', 
                    '/Zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:zipcode', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/E-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            4 => array('/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/City:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:tech:city', 
                    '/State:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:state', 
                    '/Zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:zipcode', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/E-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            5 => array('/Organization:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:organization', 
                    '/Name:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:name', 
                    '/Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:address', 
                    '/City:(?>[\x20\t]*)(.+)(?=Created)/is' => 'contacts:billing:city', 
                    '/State:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:state', 
                    '/Zip:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:zipcode', 
                    '/Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:country', 
                    '/Phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:phone', 
                    '/Fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:fax', 
                    '/E-mail:(?>[\x20\t]*)(.+)$/im' => 'contacts:billing:email'), 
            6 => array('/DNS:(?>[\x20\t]*)(.+)$/im' => 'nameserver'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/is not registered./i';
}