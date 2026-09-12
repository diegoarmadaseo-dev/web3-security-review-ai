// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract UpgradeableVaultLogic {
    address public owner;
    bool private _bootstrapped;
    uint256 public totalDeposits;

    function initialize(address newOwner) public {
        owner = newOwner;
        _bootstrapped = true;
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }

    function sweepToOwner() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(totalDeposits);
        totalDeposits = 0;
    }
}
