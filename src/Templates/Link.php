<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Link extends Regex
{

    /**
     * Blocks within the raw output of the whois
     * 
     * @var array
     * @access protected
     */
    protected $blocks = array(
            1 => '/domain name:(.*?)(?=registrant id)/is'
    );

    /**
     * Items for each block
     * 
     * @var array
     * @access protected
     */
    protected $blockItems = array(
            1 => array(
                    '/^registry expiry date:(.+)$/im' => 'expires'
            )
    );
}