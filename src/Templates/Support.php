<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;

/**
 * Template for IANA #146, #440
 *
 * @category   Whoisdoma
 * @package    WhoisParser
 */
class Support extends Regex
{

    /**
     * Blocks within the raw output of the whois
     * 
     * @var array
     * @access protected
     */
    protected $blocks = array(
        1 => '/Domain Name:(.*?)(?=Registrant ID)/is'
    );

    /**
     * Items for each block
     * 
     * @var array
     * @access protected
     */
    protected $blockItems = array(
        1 => array('/Registry Expiry Date:(?>[\x20\t]*)(.+)$/im' => 'expires')
    );
}