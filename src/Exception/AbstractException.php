<?php

namespace Whoisdoma\WhoisParser\Exception;

abstract class AbstractException extends \Exception
{

    /**
     * Creates an exception object
     * 
     * @param  string $message
     * @param  integer $code
     * @param  Exception $previous
     * @return void
     */
    public function __construct($message = '', $code = 0, Exception $previous = null)
    {
        parent::__construct($message, (int) $code, $previous);
    }
}