<?php

declare(strict_types=1);

namespace Dgtlss\Warden\Enums;

enum RuleDisposition: string
{
    case Enforced = 'enforced';
    case Advisory = 'advisory';
    case Off = 'off';
}
