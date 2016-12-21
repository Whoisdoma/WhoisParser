<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Arin extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/NetRange:(?>[\x20\t]*)(.*?)[\r\n]{2}/is', 
            2 => '/OrgName:(?>[\x20\t]*)(.*?)[\r\n]{2}/is', 
            3 => '/OrgTechHandle:(?>[\x20\t]*)(.*?)[\r\n]{2}/is', 
            4 => '/OrgAbuseHandle:(?>[\x20\t]*)(.*?)[\r\n]{2}/is', 
            5 => '/RTechHandle:(?>[\x20\t]*)(.*?)[\r\n]{2}/is', 
            6 => '/ReferralServer:(?>[\x20\t]*)(.*?)[\r\n]{2}/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/^NetRange:(?>[\x20\t]*)(.+)$/im' => 'network:inetnum', 
                    '/^NetName:(?>[\x20\t]*)(.+)$/im' => 'network:name', 
                    '/^NetHandle:(?>[\x20\t]*)(.+)$/im' => 'network:handle', 
                    '/^NetType:(?>[\x20\t]*)(.+)$/im' => 'status', 
                    '/^RegDate:(?>[\x20\t]*)(.+)$/im' => 'created', 
                    '/^Updated:(?>[\x20\t]*)(.+)$/im' => 'changed'), 
            2 => array('/^OrgId:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:handle', 
                    '/^OrgName:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:organization', 
                    '/^Address:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:address', 
                    '/^City:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:city', 
                    '/^StateProv:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:state', 
                    '/^PostalCode:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:zipcode', 
                    '/^Country:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:country', 
                    '/^RegDate:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:created', 
                    '/^Updated:(?>[\x20\t]*)(.+)$/im' => 'contacts:owner:changed'), 
            3 => array('/^OrgTechHandle:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:handle', 
                    '/^OrgTechName:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:name', 
                    '/^OrgTechPhone:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:phone', 
                    '/^OrgTechEmail:(?>[\x20\t]*)(.+)$/im' => 'contacts:tech:email'), 
            4 => array('/^OrgAbuseHandle:(?>[\x20\t]*)(.+)$/im' => 'contacts:abuse:handle', 
                    '/^OrgAbuseName:(?>[\x20\t]*)(.+)$/im' => 'contacts:abuse:name', 
                    '/^OrgAbusePhone:(?>[\x20\t]*)(.+)$/im' => 'contacts:abuse:phone', 
                    '/^OrgAbuseEmail:(?>[\x20\t]*)(.+)$/im' => 'contacts:abuse:email'), 
            5 => array('/^RTechHandle:(?>[\x20\t]*)(.+)$/im' => 'contacts:rtech:handle', 
                    '/^RTechName:(?>[\x20\t]*)(.+)$/im' => 'contacts:rtech:name', 
                    '/^RTechPhone:(?>[\x20\t]*)(.+)$/im' => 'contacts:rtech:phone', 
                    '/^RTechEmail:(?>[\x20\t]*)(.+)$/im' => 'contacts:rtech:email'), 
            6 => array('/^ReferralServer:(?>[\x20\t]*)(.+)$/im' => 'referral_server'));

    /**
     * After parsing do something
     *
     * If ARNIC says the organization is different change the whois server and
     * restart parsing.
     *
     * @param  object &$WhoisParser
     * @return void
     */
    public function postProcess(&$WhoisParser)
    {
        $Result = $WhoisParser->getResult();
        $Config = $WhoisParser->getConfig();
        
        foreach ($Result->contacts as $contactType => $contactObject) {
            foreach ($contactObject as $contact) {
                if (isset($contact->handle) && $contact->handle === 'AFRINIC') {
                    $Result->reset();
                    $Config->setCurrent($Config->get('afrinic'));
                    $WhoisParser->call();
                }
            }
        }
        
        if (isset($Result->referral_server) && $Result->referral_server != '') {
            $Result->reset();
            $mapping = $Config->get($Result->referral_server);
            $template = str_replace('whois://', '', $mapping['template']);
            $Config->setCurrent($Config->get($template));
            $WhoisParser->call();
        }
    }
}