// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract SpotPriceLending {
    IPair public immutable collateralPair;
    mapping(address => uint256) public collateralDeposited;
    mapping(address => uint256) public borrowed;

    uint256 public constant LIQUIDATION_THRESHOLD_BPS = 8000;

    constructor(address pair) {
        collateralPair = IPair(pair);
    }

    function _currentPrice() internal view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = collateralPair.getReserves();
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    function isLiquidatable(address account) public view returns (bool) {
        uint256 collateralValue = (collateralDeposited[account] * _currentPrice()) / 1e18;
        uint256 debt = borrowed[account];
        return debt * 10000 > collateralValue * LIQUIDATION_THRESHOLD_BPS;
    }

    function deposit() external payable {
        collateralDeposited[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        borrowed[msg.sender] += amount;
    }

    function liquidate(address account) external {
        require(isLiquidatable(account), "healthy position");
        uint256 seizedCollateral = collateralDeposited[account];
        collateralDeposited[account] = 0;
        borrowed[account] = 0;
        payable(msg.sender).transfer(seizedCollateral);
    }
}
