// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;
interface TokenFixture {
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 value) external;
    function transferFrom(address from, address to, uint256 value) external;
}
// Receipt/ABI fixture only; no oracle or production authorization claim.
contract BridgeFixture {
    struct Cap { uint128 total; uint128 perLock; uint128 hourly; uint128 daily; }
    event Lock(address indexed from, address indexed token, bytes32 indexed to, uint256 amount, uint256 balance, uint8 decimals, uint64 nonce, uint32 generation);
    event Unlock(address indexed token, bytes32 owner, bytes32 indexed txHash, uint64 lt, address indexed to, uint256 value, uint256 balance);
    event LockRefunded(uint64 indexed nonce, address indexed locker, address indexed token, uint256 value);
    function getLockCapState(address) external pure returns (Cap memory cap, uint256 hourUsed, uint256 dayUsed, uint256 available) {
        return (Cap(1000000e6, 100e6, 1000e6, 10000e6), 0, 0, 100e6);
    }
    function deposit(address token, uint256 value) external {
        uint256 beforeBalance = TokenFixture(token).balanceOf(address(this));
        TokenFixture(token).transferFrom(msg.sender, address(this), value);
        uint256 afterBalance = TokenFixture(token).balanceOf(address(this));
        emit Lock(msg.sender, token, bytes32(0), afterBalance - beforeBalance, afterBalance, 6, 1, 1);
    }
    function payout(address token, address to, uint256 value) external {
        TokenFixture(token).transfer(to, value);
        emit Unlock(token, bytes32(0), bytes32(0), 1, to, value, TokenFixture(token).balanceOf(address(this)));
    }
    function refund(address token, address to, uint256 value) external {
        TokenFixture(token).transfer(to, value);
        emit LockRefunded(2, to, token, value);
    }
}
