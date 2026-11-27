// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

// Isolated issuer ABI/storage fixture, not a production proxy implementation.
contract StandardObserverFixture {
    bytes32 constant SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    address public owner;
    bool public paused;
    mapping(address => bool) public isBlacklisted;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Paused(address account);
    constructor() { owner = msg.sender; balanceOf[msg.sender] = 1000000000000; }
    modifier onlyOwner() { require(msg.sender == owner, "fixture owner"); _; }
    function setImplementation(address target) external onlyOwner { assembly { sstore(SLOT, target) } }
    function addBlackList(address who) external onlyOwner { isBlacklisted[who] = true; }
    function pause() external onlyOwner { paused = true; emit Paused(msg.sender); }
    function unpause() external onlyOwner { paused = false; }
    function approve(address who, uint256 value) external returns (bool) { allowance[msg.sender][who] = value; return true; }
    function move(address from, address to, uint256 value) internal {
        require(!paused && !isBlacklisted[from] && !isBlacklisted[to], "blocked");
        balanceOf[from] -= value; balanceOf[to] += value; emit Transfer(from, to, value);
    }
    function transfer(address to, uint256 value) external returns (bool) { move(msg.sender, to, value); return true; }
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        allowance[from][msg.sender] -= value; move(from, to, value); return true;
    }
}
