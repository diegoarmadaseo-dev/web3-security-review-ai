// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract CreditLedger {
    address public issuer;
    mapping(address => uint256) public credits;

    modifier onlyIssuer() {
        require(msg.sender == issuer, "not issuer");
        _;
    }

    constructor() {
        issuer = msg.sender;
    }

    function issueCredit(address to, uint256 amount) external onlyIssuer {
        credits[to] += amount;
    }

    function spendCredit(uint256 amount) external {
        unchecked {
            credits[msg.sender] -= amount;
        }
    }
}
