<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Kz extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/Organization Using Domain Name(.*?)(?=Administrative Contact\/Agent)/is', 
            2 => '/Administrative Contact\/Agent(.*?)(?=Nameserver in listed order)/is', 
            3 => '/Nameserver in listed order(.*?)(?=Domain created)/is', 
            4 => '/Domain created(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/^Name(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/^Organization Name(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^Street Address(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^City(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:city', 
                    '/^State(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:state', 
                    '/^Postal Code(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:zipcode', 
                    '/^City(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:owner:city'), 
            2 => array(
                    '/^NIC Handle(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:handle', 
                    '/^Name(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.*)$/im' => 'contacts:admin:name', 
                    '/^Phone Number(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:phone', 
                    '/^Fax Number(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:fax', 
                    '/^Email Address(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'contacts:admin:email'), 
            3 => array(
                    '/^(Primary|Secondary) server(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/^(Primary|Secondary) ip address(?>[\.]*)(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'ips'), 
            4 => array('/^Last modified(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/^Domain created(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Domain status(?>[\x20\t]*):(?>[\x20\t]*)(.+)$/im' => 'status'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Nothing found for this query/i';
}