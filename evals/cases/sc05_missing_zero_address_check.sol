// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract FeeCollector {
    address public owner;
    address public feeRecipient;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        feeRecipient = msg.sender;
    }

    function setFeeRecipient(address newRecipient) external onlyOwner {
        feeRecipient = newRecipient;
    }

    function collectFee() external payable {
        payable(feeRecipient).transfer(msg.value);
    }
}
