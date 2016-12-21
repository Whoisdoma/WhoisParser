<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Icb extends Regex
{
    protected $convertFromHtml = true;

    /**
     * Cut block from HTML output for $blocks
     * 
     * @var string
     * @access protected
     */
    protected $htmlBlock = '/<!--- ### --->(.*?)<!--- ### --->/is';

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/Domain Information(.*?)(?=Admin Contact)/is', 
            2 => '/Admin Contact(.*?)(?=Technical Contact)/is', 
            3 => '/Technical Contact(.*?)(?=Billing Contact)/is', 
            4 => '/Primary Nameserver(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/Organization Name:\n(?>[\x20\t]*)(.+)/i' => 'contacts:owner:organization', 
                    '/Street:\n(?>[\x20\t]*)(.+)/i' => 'contacts:owner:address', 
                    '/City:\n(?>[\x20\t]*)(.+)/i' => 'contacts:owner:city', 
                    '/State:\n(?>[\x20\t]*)(.+)/i' => 'contacts:owner:state', 
                    '/Postal Code:\n(?>[\x20\t]*)(.+)/i' => 'contacts:owner:zipcode', 
                    '/Country:\n(?>[\x20\t]*)(.+)/i' => 'contacts:owner:country', 
                    '/Created:\n(?>[\x20\t]*)(.+)/i' => 'created', 
                    '/Last Updated:\n(?>[\x20\t]*)(.+)/i' => 'changed', 
                    '/Expires:\n(?>[\x20\t]*)(.+)/i' => 'expires'), 
            2 => array('/User ID:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:handle', 
                    '/Contact Name:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:name', 
                    '/Organization Name:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:organization', 
                    '/Street:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:address', 
                    '/City:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:city', 
                    '/State:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:state', 
                    '/Postal Code:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:zipcode', 
                    '/Country:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:country', 
                    '/Phone:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:phone', 
                    '/Fax:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:fax', 
                    '/E-Mail:\n(?>[\x20\t]*)(.+)/i' => 'contacts:admin:email'), 
            3 => array('/User ID:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:handle', 
                    '/Contact Name:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:name', 
                    '/Organization Name:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:organization', 
                    '/Street:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:address', 
                    '/City:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:city', 
                    '/State:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:state', 
                    '/Postal Code:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:zipcode', 
                    '/Country:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:country', 
                    '/Phone:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:phone', 
                    '/Fax:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:fax', 
                    '/E-Mail:\n(?>[\x20\t]*)(.+)/i' => 'contacts:tech:email'), 
            4 => array('/Nameserver:\n(?>[\x20\t]*)(.+)/i' => 'nameserver', 
                    '/IP Address:\n(?>[\x20\t]*)(.+)/i' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/(There is no live registration)/i';


    public function translateRawData($rawdata, $config)
    {
        return strip_tags($rawdata);
    }
}
