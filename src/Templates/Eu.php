<?php
namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Eu extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/technical:\n(.*?)(?=registrar)/is', 
            2 => '/registrar:\n(.*?)(?=name servers)/is', 3 => '/name servers:\n(.*?)(?=keys:)/is', 
            4 => '/keys:\n(.*?)(?=Please visit)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/organisation:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:organization', 
                    '/language:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:language', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/email:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            2 => array('/name:(?>[\x20\t]*)(.+)$/im' => 'registrar:name', 
                    '/website:(?>[\x20\t]*)(.+)$/im' => 'registrar:url'), 
            3 => array('/\n(?>[\x20\t]+)(.+)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+)(.+) \(.+\)$/im' => 'nameserver', 
                    '/\n(?>[\x20\t]+).+ \((.+)\)$/im' => 'ips'), 
            4 => array('/keyTag:(.+)$/im' => 'dnssec'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/Status:(?>[\x20\t]*)AVAILABLE/i';

    /**
     * After parsing ...
     * 
     * If dnssec key was found we set attribute to true
     * 
	 * @param  object &$WhoisParser
	 * @return void
	 */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
    }
}