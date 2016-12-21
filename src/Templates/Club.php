<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Club extends Regex
{

    /**
     * Blocks within the raw output of the whois
     * 
     * @var array
     * @access protected
     */
    protected $blocks = array(
            1 => '/created by registrar(.*?)(?=name value pair)/is');

    /**
     * Items for each block
     * 
     * @var array
     * @access protected
     */
    protected $blockItems = array(
            1 => array(
                    '/^domain expiration date:(?>[\x20\t]*)(.+)$/im' => 'expires'
            )
    );
}