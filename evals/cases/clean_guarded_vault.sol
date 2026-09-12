// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title GuardedVault
/// @notice A minimal deposit/withdraw vault with straightforward, correctly
///         applied access control and checks-effects-interactions ordering.
contract GuardedVault {
    address public immutable owner;
    mapping(address => uint256) public balances;
    bool private _locked;

    modifier onlyOwner() {
        require(msg.sender == owner, "GuardedVault: not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "GuardedVault: reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "GuardedVault: insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "GuardedVault: transfer failed");
    }

    function rescueToken(address token, address to, uint256 amount) external onlyOwner {
        require(to != address(0), "GuardedVault: zero address");
        (bool ok, bytes memory data) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "GuardedVault: token transfer failed");
    }
}
