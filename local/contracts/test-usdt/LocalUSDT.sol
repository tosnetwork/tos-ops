// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

interface LegacyTarget {
    function transferByLegacy(address from, address to, uint256 value) external;
    function transferFromByLegacy(address sender, address from, address to, uint256 value) external;
    function approveByLegacy(address from, address spender, uint256 value) external;
    function balanceOf(address account) external view returns (uint256);
    function allowance(address from, address spender) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

// Local behavioural fixture, not issuer code or a release asset. No proxy.
// Sender-only blacklist checks intentionally allow deposits into a frozen bridge.
contract LocalUSDT {
    string public constant name = "Local test USDT";
    string public constant symbol = "tUSDT";
    uint256 public constant decimals = 6;
    address public owner;
    uint256 private supply;
    uint256 public basisPointsRate;
    uint256 public maximumFee;
    bool public paused;
    bool public deprecated;
    address public upgradedAddress;
    mapping(address => uint256) private balances;
    mapping(address => mapping(address => uint256)) private allowed;
    mapping(address => bool) public isBlackListed;
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    event DestroyedBlackFunds(address account, uint256 amount);
    event Pause();
    event Unpause();
    event Deprecate(address upgradedAddress);
    event Params(uint256 feeBasisPoints, uint256 maxFee);

    constructor(uint256 amount) {
        require(block.chainid == 1, "local source chain only");
        owner = msg.sender;
        balances[msg.sender] = amount;
        supply = amount;
        emit Transfer(address(0), msg.sender, amount);
    }
    modifier onlyOwner() {
        require(msg.sender == owner, "not fixture owner");
        _;
    }
    function setParams(uint256 basisPoints, uint256 maxFee) external onlyOwner {
        require(basisPoints < 20 && maxFee < 50, "fee bounds");
        basisPointsRate = basisPoints;
        maximumFee = maxFee * 10 ** decimals;
        emit Params(basisPointsRate, maximumFee);
    }
    function pause() external onlyOwner { require(!paused, "paused"); paused = true; emit Pause(); }
    function unpause() external onlyOwner { require(paused, "not paused"); paused = false; emit Unpause(); }
    function addBlackList(address account) external onlyOwner { isBlackListed[account] = true; }
    function removeBlackList(address account) external onlyOwner { isBlackListed[account] = false; }
    function destroyBlackFunds(address account) external onlyOwner {
        require(isBlackListed[account], "not blacklisted");
        uint256 amount = balanceOf(account);
        balances[account] = 0;
        supply -= amount;
        // Deliberately no Transfer event: monitoring must read the issuer event.
        emit DestroyedBlackFunds(account, amount);
    }
    function deprecate(address target) external onlyOwner {
        deprecated = true;
        upgradedAddress = target;
        emit Deprecate(target);
    }
    function balanceOf(address account) public view returns (uint256) {
        return deprecated ? LegacyTarget(upgradedAddress).balanceOf(account) : balances[account];
    }
    function totalSupply() external view returns (uint256) {
        return deprecated ? LegacyTarget(upgradedAddress).totalSupply() : supply;
    }
    function allowance(address from, address spender) external view returns (uint256) {
        return deprecated ? LegacyTarget(upgradedAddress).allowance(from, spender) : allowed[from][spender];
    }
    function approve(address spender, uint256 amount) external {
        if (deprecated) {
            LegacyTarget(upgradedAddress).approveByLegacy(msg.sender, spender, amount);
        } else {
            require(amount == 0 || allowed[msg.sender][spender] == 0, "clear allowance first");
            allowed[msg.sender][spender] = amount;
            emit Approval(msg.sender, spender, amount);
        }
    }
    function transfer(address to, uint256 amount) external {
        require(!paused && !isBlackListed[msg.sender], "sender frozen or paused");
        if (deprecated) LegacyTarget(upgradedAddress).transferByLegacy(msg.sender, to, amount);
        else _transfer(msg.sender, to, amount);
    }
    function transferFrom(address from, address to, uint256 amount) external {
        require(!paused && !isBlackListed[from], "sender frozen or paused");
        if (deprecated) {
            LegacyTarget(upgradedAddress).transferFromByLegacy(msg.sender, from, to, amount);
        } else {
            uint256 permitted = allowed[from][msg.sender];
            if (permitted < type(uint256).max) allowed[from][msg.sender] = permitted - amount;
            _transfer(from, to, amount);
        }
    }
    function _transfer(address from, address to, uint256 amount) internal {
        uint256 fee = amount * basisPointsRate / 10000;
        if (fee > maximumFee) fee = maximumFee;
        balances[from] -= amount;
        balances[to] += amount - fee;
        if (fee != 0) {
            balances[owner] += fee;
            emit Transfer(from, owner, fee);
        }
        emit Transfer(from, to, amount - fee);
    }
}
