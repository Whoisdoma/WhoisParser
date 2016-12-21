<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

class Jp extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/\[(registrant|organization)\](?>[\x20\t]*)(.*?)$/im', 
            2 => '/\[name server\](?>[\x20\t]*)(.*?)(?=contact information:|$)/is', 
            3 => '/contact information:(?>[\x20\t]*)(.*?)$/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array(
                    '/\[(registrant|organization)\](?>[\x20\t]*)(.*?)$/im' => 'contacts:owner:organization'), 
            2 => array('/\[name server\](?>[\x20\t]*)(.+)$/im' => 'nameserver', 
                    '/\[signing key\](?>[\x20\t]*)(.+)$/im' => 'dnssec', 
                    '/\[(created on|registered date)\](?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/\[expires on\](?>[\x20\t]*)(.+)$/im' => 'expires', 
                    '/\[(status|state)\](?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/\[last (update|updated)\](?>[\x20\t]*)(.+)$/im' => 'changed'), 
            3 => array('/\[name\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:name', 
                    '/\[email\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:email', 
                    '/\[postal code\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^(\[postal address\])?(?>[\x20\t]+)(.+)$/im' => 'contacts:owner:address', 
                    '/\[phone\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:phone', 
                    '/\[fax\](?>[\x20\t]*)(.+)$/im' => 'contacts:owner:fax'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/No match!!/i';

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
        
        if ($ResultSet->dnssec != '') {
            $ResultSet->dnssec = true;
        } else {
            $ResultSet->dnssec = false;
        }
    }
}