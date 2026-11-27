// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;
import "LocalUSDT.sol";

// Local issuer-interface fixture only; no production asset or proxy claim.
contract StandardIssuerFixture is LocalUSDT {
    constructor() LocalUSDT(1000000000000) {}
    function isBlacklisted(address who) external view returns (bool) {
        return isBlackListed[who];
    }
}
