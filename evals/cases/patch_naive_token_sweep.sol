// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract DonationSweeper {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Forwards a donated token balance to the owner. Must keep working
    ///         for every ERC20-shaped token the community might donate, including
    ///         ones that do not strictly follow the standard's return-value rules.
    function sweep(address token, uint256 amount) external onlyOwner {
        IToken(token).transfer(owner, amount);
    }
}
