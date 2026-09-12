// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract TreasuryVault {
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdrawAll(address payable to) external {
        uint256 balance = address(this).balance;
        to.transfer(balance);
    }
}
