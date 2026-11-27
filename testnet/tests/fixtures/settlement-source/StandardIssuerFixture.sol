// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

// Local issuer-interface fixture only; no production asset or proxy claim.
contract StandardIssuerFixture {
    address public owner;
    bool public paused;
    mapping(address => bool) public isBlacklisted;
    mapping(address => uint256) public balanceOf;
    constructor() { owner = msg.sender; balanceOf[msg.sender] = 1000000000000; }
    modifier onlyOwner() { require(msg.sender == owner, "not fixture owner"); _; }
    function addBlackList(address who) external onlyOwner { isBlacklisted[who] = true; }
    function removeBlackList(address who) external onlyOwner { isBlacklisted[who] = false; }
    function pause() external onlyOwner { paused = true; }
    function unpause() external onlyOwner { paused = false; }
    function transfer(address to, uint256 value) external returns (bool) {
        require(!paused && !isBlacklisted[msg.sender] && !isBlacklisted[to], "blocked");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }
}
