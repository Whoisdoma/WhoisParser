<?php
namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Es extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain name:(?>[\x20\t]*)(.*?)(?=registrant:)/is', 
            2 => '/registrant name:(?>[\x20\t]*)(.*?)(?=domain servers)/is', 
            3 => '/domain servers:(?>[\x20\t]*)(.*?)(?=\>\>\> last update)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/creation date:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires'), 
            2 => array('/registrant name:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name'), 
            3 => array('/name server [0-9]:(?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/ipv4 server [0-9]:(?>[\x20\t]*)(.+)$/im' => 'ips'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/there is no information available on/i';

    protected $rateLimit = '/is not authorised  or  has exceeded the established limit/im';
}