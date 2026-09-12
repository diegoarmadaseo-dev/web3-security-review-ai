// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./ExternalRegistry.sol";

contract MembershipVault is ExternalRegistry {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        require(isMember(msg.sender), "not a registered member");
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
