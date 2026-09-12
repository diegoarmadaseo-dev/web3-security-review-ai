// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract RewardPool {
    address public operator;
    uint256 public totalShares;
    uint256 public totalRewards;
    mapping(address => uint256) public shares;

    modifier onlyOperator() {
        require(msg.sender == operator, "not operator");
        _;
    }

    constructor() {
        operator = msg.sender;
    }

    function deposit(uint256 shareAmount) external {
        shares[msg.sender] += shareAmount;
        totalShares += shareAmount;
    }

    function fundRewards(uint256 amount) external payable onlyOperator {
        require(msg.value == amount, "amount must match value sent");
        totalRewards += amount;
    }

    function calculateReward(address account) public view returns (uint256) {
        return (shares[account] / totalShares) * totalRewards;
    }

    function claimReward() external {
        uint256 reward = calculateReward(msg.sender);
        shares[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
    }

    receive() external payable {}
}
