// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract SimpleVesting {
    address public beneficiary;
    uint256 public totalAllocation;
    uint256 public startTime;
    uint256 public duration;

    constructor(address _beneficiary, uint256 _totalAllocation, uint256 _duration) {
        beneficiary = _beneficiary;
        totalAllocation = _totalAllocation;
        duration = _duration;
        startTime = block.timestamp;
    }

    function vestedAmount() public view returns (uint256) {
        if (block.timestamp >= startTime + duration) {
            return totalAllocation;
        }
        return (totalAllocation * (block.timestamp - startTime)) / duration;
    }

    function release() external {
        require(msg.sender == beneficiary, "not beneficiary");
        uint256 amount = vestedAmount();
        (bool ok, ) = beneficiary.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
