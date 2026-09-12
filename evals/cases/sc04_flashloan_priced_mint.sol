// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IFlashLoanProvider {
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external;
}

contract SyntheticMinter {
    IPair public immutable pricingPair;
    mapping(address => uint256) public syntheticBalance;

    constructor(address pair) {
        pricingPair = IPair(pair);
    }

    function onFlashLoan(address, uint256, uint256, bytes calldata data) external returns (bytes32) {
        (uint256 collateralAmount) = abi.decode(data, (uint256));
        mintAgainstCollateral(collateralAmount);
        return keccak256("ERC3156FlashBorrower.onFlashLoanCallback");
    }

    function mintAgainstCollateral(uint256 collateralAmount) public {
        (uint112 reserve0, uint112 reserve1, ) = pricingPair.getReserves();
        uint256 price = (uint256(reserve1) * 1e18) / uint256(reserve0);
        uint256 mintAmount = (collateralAmount * price) / 1e18;
        syntheticBalance[msg.sender] += mintAmount;
    }
}
