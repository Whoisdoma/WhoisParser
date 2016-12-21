<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Pl extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(
            1 => '/domain name:(?>[\x20\t]*)(.*?)(?=technical contact:|registrar:)/is', 
            2 => '/technical contact:(?>[\x20\t]*)(.*?)(?=registrar:)/is', 
            3 => '/registrar:(?>[\x20\t]*)(.*?)(?=WHOIS displays data)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^(nameservers:)?(?>[\x20\t]+)(.+)\./im' => 'nameserver', 
                    '/^(nameservers:)?(?>[\x20\t]+)(.+)\. \[.+\]/im' => 'nameserver', 
                    '/^created:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/last modified:(?>[\x20\t]*)(.+)$/im' => 'changed', 
                    '/renewal date:(?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/dnssec:(?>[\x20\t]*)(.+)$/im' => 'dnssec'), 
            
            2 => array('/company:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^(?>[\x20\t]+)(.+)$/im' => 'contacts:tech:organization', 
                    '/street:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:address', 
                    '/city:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:city', 
                    '/location:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:country', 
                    '/handle:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/phone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/fax:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:fax', 
                    '/last modified:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:changed'), 
            
            3 => array('/registrar:\n(.*)$/im' => 'registrar:name', 
                    '/(?=fax:).+\n(.+)\n\n$/is' => 'registrar:email'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No information available about domain/i';

    /**
     * After parsing ...
     * 
     * If dnssec key was found we set attribute to true.
     * 
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        
        if ($ResultSet->dnssec === 'Unsigned') {
            $ResultSet->dnssec = false;
        } else {
            $ResultSet->dnssec = true;
        }
    }
}