# Dahlia Audit Findings

In January of 2025, I participated in Dahlia's audit contest on Cantina securing [**1st place 🏆**](https://cantina.xyz/competitions/691ce303-f137-437a-bf34-aef87dfe983b/leaderboard) with 1 High Severity Finding and 5 Medium Severity Findings.

## Table of contents
| Severity | Title |
|:--------:|-------|
| **High** | [[H-01] withdraw subtracts principal amount wrongly](#h-01-withdraw-subtracts-principal-amount-wrongly) |
| **Medium** | [[M-01] Malicious users can bypass 100% of the flashloan fee and take a flashloan for free](#m-01-malicious-users-can-bypass-100-of-the-flashloan-fee-and-take-a-flashloan-for-free) |
| **Medium** | [[M-02] Wrong values used in calculations for collateral refunds](#m-02-wrong-values-used-in-calculations-for-collateral-refunds) |
| **Medium** | [[M-03] `updateLiquidationBonusRate` may clash with liquidators deciding whether to liquidate](#m-03-updateliquidationbonusrate-may-clash-with-liquidators-deciding-whether-to-liquidate) |
| **Medium** | [[M-04] setRewardsInterval should ensure that `start >= block.timestamp`](#m-04-setrewardsinterval-should-ensure-that-start--blocktimestamp) |
| **Medium** | [[M-05] Rewards in WrappedVault could be lost due to `internalWithdrawDepositAndClaimCollateral` not updating all variables properly](#m-05-rewards-in-wrappedvault-could-be-lost-due-to-internalwithdrawdepositandclaimcollateral-not-updating-all-variables-properly) |

----

## [H-01] `withdraw` subtracts principal amount wrongly

### Vulnerability Details

```solidity
function withdraw(MarketId id, uint256 assets, uint256 shares, address receiver, address owner) external nonReentrant returns (uint256, uint256) {
    require(receiver != address(0), Errors.ZeroAddress());
    MarketData storage marketData = markets[id];
    Market storage market = marketData.market;
    IDahliaWrappedVault vault = market.vault;
    _permittedByWrappedVault(vault);
    _validateMarketIsActiveOrPausedOrDeprecated(market.status);
    mapping(address => UserPosition) storage positions = marketData.userPositions;
    _accrueMarketInterest(id, positions, market);
    UserPosition storage ownerPosition = positions[owner];

    (uint256 _assets, uint256 _shares, uint256 ownerLendShares) = LendImpl.internalWithdraw(id, market, ownerPosition, assets, shares, owner, receiver);

    // User lend assets should be 0 if no shares are left (rounding issue)
    uint256 userLendAssets = ownerPosition.lendPrincipalAssets;
    if (ownerLendShares == 0) {
        ownerPosition.lendPrincipalAssets = 0;
        market.totalLendPrincipalAssets -= userLendAssets;
    } else {
-->     uint256 userLendAssetsDown = FixedPointMathLib.min(_assets, userLendAssets);
-->     ownerPosition.lendPrincipalAssets = (userLendAssets - userLendAssetsDown).toUint128();
        market.totalLendPrincipalAssets -= userLendAssetsDown;
    }

    return (_assets, _shares);
}
```
Focusing on the 2 lines marked with an `-->`. When the user is doing a partial withdraw like say 10% of funds, `userLendAssetsDown` will always be set to `_assets` as it will likely be the min. (unless the funds was sitting in the contract for so long that 10% of the funds has accrued interest to the extend that it exceeds the user's total lend principal assets)

`ownerPosition.lendPrincipalAssets` is then subtracted by it. However, `ownerPosition.lendPrincipalAssets` is supposed **to exclude interest**. So by subtracting it with a variable that includes interest, it then leads to an incorrect value.

### Impact
`ownerPosition.lendPrincipalAssets` is suppposed to be a variable that excludes interest and it is used in the calculation of rewards distribution in the vault.

The incorrect resultant value of `ownerPosition.lendPrincipalAssets` will lead to the wrapped vault distribution of rewards to be inaccurate.

----

## [M-01] Malicious users can bypass 100% of the flashloan fee and take a flashloan for free

### Vulnerability Details

In dahlia, flashloan fees are allowed to go up to 3% of the amount loaned and it is given to the protocol fee recipient.

The 3% is a big amount as amounts taken up in flashloans are generally a really big amount. For example an user may want to flashloan a big amount like 10 million usdc which is what flashloans are for. A malicious bypass of the 3% fee in this case would be **a $300,000 loss for the protocol fee recipient**.

```solidity
function flashLoan(address token, uint256 assets, bytes calldata callbackData) external {
    require(assets != 0, Errors.ZeroAssets());
    token.safeTransfer(msg.sender, assets);
    _flashLoan(address(this), token, assets, callbackData);
}
```

There are 2 flashloan functions, the one i pasted above is for taking a flashloan of tokens that are sitting in address(Dahlia.sol)'s balance. 

The tokens will be collateral tokens in this case since collateral tokens are the ones that are stored in address(Dahlia.sol)'s balance.

However we can see that in `supplyCollateral`, it gives the user a callback before transferring the collateral tokens from the user.
```solidity
function supplyCollateral(MarketId id, uint256 assets, address owner, bytes calldata callbackData) external {
    require(assets > 0, Errors.ZeroAssets());
    require(owner != address(0), Errors.ZeroAddress());
    MarketData storage marketData = markets[id];
    Market storage market = marketData.market;
    _validateMarketIsActive(market.status);
    /// @dev accrueInterest is not needed here.

    BorrowImpl.internalSupplyCollateral(id, market, marketData.userPositions[owner], assets, owner);

    if (callbackData.length > 0 && address(msg.sender).code.length > 0) {
        IDahliaSupplyCollateralCallback(msg.sender).onDahliaSupplyCollateral(assets, callbackData);
    }

    market.collateralToken.safeTransferFrom(msg.sender, address(this), assets);
}
```

### Attack path for free flashloan
Suppose there are `Vault A, B and C` in Dahlia with collateral token `WETH`.

And that they have around `100,000` WETH combined. (The WETH will be sitting in address(Dahlia.sol) as unlike deposit assets, collateral tokens sit in address(Dahlia.sol)'s balance)

Instead of flashloaning from `flashloan` and incurring 3% fee, the malicious user does this instead:
  * On any of the Vault (could be A,B or C, doesn't matter) the user calls `supplyCollateral(assets = 100,000 WETH)`
  * `supplyCollateral` updates the user as having `100,000 WETH` in collateral deposited through `BorrowImpl.internalSupplyCollateral` even though the user **has yet to transfer it**.
  * The callback `onDahliaSupplyCollateral` occurs **before** the code pulls token from the user.
  * During the callback, the user calls `withdrawCollateral` to get `100,000 WETH` that is in the contract balance.
  * The user then does whatever they intend to do with that big sum of money in one transaction (basically what they had intended to do in a normal flashloan)
  * Then the last line of `supplyCollateral` runs and the 100,000 WETH is returned from the user to protocol. **However, now the user has sucessfully avoided the flashloan fee of `3000 WETH`**.

Note that this **is not a whale attack** as shown by the attack path above, the user **does not** need to have any starting capital at all as the user takes the 100,000 WETH first before returning it.

### Recommendation
Add `nonReentrant` to both `supplyCollateral` and `withdrawCollateral`. That way, malicious users will not be able to jump from one function to the other and cause a 3% loss for protocol fee recipient.

----

## [M-02] Wrong values used in calculations for collateral refunds

### Vulnerability Details
Users calling `withdrawDepositAndClaimCollateral` gets to withdraw their proportionate share of `lendAssets` and `collateralAssets` to make up for the unrepaid loans.

The amount the user will receive is calculated by `LendImpl.internalWithdrawDepositAndClaimCollateral`
```solidity
function internalWithdrawDepositAndClaimCollateral(
    IDahlia.MarketId id,
    IDahlia.Market storage market,
    IDahlia.UserPosition storage ownerPosition,
    address owner,
    address receiver
) internal returns (uint256 lendAssets, uint256 collateralAssets) {
      uint256 shares = ownerPosition.lendShares;
      require(shares > 0, Errors.ZeroAssets());
      uint256 totalCollateralAssets = market.totalCollateralAssets;
      uint256 totalLendAssets = market.totalLendAssets;
      uint256 totalLendShares = market.totalLendShares;

      // calculate owner assets based on liquidity in the market
      lendAssets = shares.toAssetsDown(totalLendAssets - market.totalBorrowAssets, totalLendShares);
      // Calculate owed collateral based on lendPrincipalAssets
-->   collateralAssets = (ownerPosition.lendPrincipalAssets * totalCollateralAssets) / market.totalLendPrincipalAssets;

      market.vault.burnShares(owner, ownerPosition.lendPrincipalAssets);
      ownerPosition.lendShares = 0;
      ownerPosition.lendPrincipalAssets = 0;
      market.totalLendShares = totalLendShares - shares;
      market.totalLendAssets = totalLendAssets - lendAssets;

      emit IDahlia.WithdrawDepositAndClaimCollateral(id, msg.sender, receiver, owner, lendAssets, collateralAssets, shares);
}
```

In the line pointed out by the arrow: `collateralAssets = (ownerPosition.lendPrincipalAssets * totalCollateralAssets) / market.totalLendPrincipalAssets`

The amount of collateral received by the user is calculated using the principal assets which does not include the interest earned.

### Impact
Suppose there are 2 users `Alice` and `Bob` who both lent out `5 ether`.
  * `Alice` started lending on Day 1 while `Bob` started lending on Day 8
  * However, the collateral received by `Alice` will be the same as the collateral received by `Bob` because principalAssets are used in the calculation. (And that is the variable that does not 
  * This is unfair for `Alice` as `Alice` is supposed to have 7 extra days of interest compared to `Bob` and hence should receive a great share of the collateral pie than `Bob`.

Now, both users end up receiving the same amount even though one user lent out many days earlier and should rightfully have earned so much more in interest compared to the other user.

### Recommendation
Use `ownerPosition.lendShares` and `market.totalLendShares` to calculate the share of the collateral pie that each user should receive.

```diff
-  collateralAssets = (ownerPosition.lendPrincipalAssets * totalCollateralAssets) / market.totalLendPrincipalAssets;
+  collateralAssets = (ownerPosition.lendShares * totalCollateralAssets) / market.totalLendShares;
```

----

## [M-03] `updateLiquidationBonusRate` may clash with liquidators deciding whether to liquidate

### Vulnerability Details
`updateLiquidationBonusRate` updates the bonus that the liquidator will get when they choose to liquidate a loan that they see is underwater.

When a liquidator sees a loan that is underwater, they weigh the revenue and costs in order to decide on whether to call liquidate.

What they gain:
  * Bonus from the liquidation in the form of `liquidateBonusRate`.
What they lose:
  * Gas fee from calling `liquidate`
  * Gas fee + slippage loss because they need to provide the full amount of `loanToken` taken on in the debt. Since they may not have `loanToken` it is common that they swap their existing tokens to `loanToken` in order to be able to call `liquidate`.

As shown there's a form of weighing before the liquidator decides if it will be profitable to call `liquidate`.

### Impact
If a liquidator weighs the revenue and costs and decides to call `liquidate`. The admin might also end non-intentionally calling `updateLiquidationBonusRate` to do a normal bonus update at around the same time.

If `updateLiquidationBonusRate` ends up being processed first then the liquidator may get lesser revenue in return, perhaps now even lesser than the 2 cost avenues decsribed above, leading to net loss for the liquidator.

### Likelihood
The likelihood is also not that low as in market corrections, `liquidate` being called is something common and will likely be happening almost every minute. As long as the admin updates the bonus liquidate rate, there is a chance that the clash could occur leading to a wrong choice due to asymmetrical information.

### Recommendation
Add a slippage check in `liquidate` due to the dynamic nature of the bonus.

----

## [M-04] `setRewardsInterval` should ensure that `start >= block.timestamp`

### Vulnerability Details
```solidity
function setRewardsInterval(address reward, uint256 start, uint256 end, uint256 totalRewards, address frontendFeeRecipient) external payable onlyOwner {
    if (!isReward[reward]) revert InvalidReward();
    if (start >= end) revert IntervalEndBeforeStart();
    if (end <= block.timestamp) revert IntervalEndInPast();
    if (start == 0) revert IntervalStartIsZero();
    if ((end - start) < MIN_CAMPAIGN_DURATION) revert InvalidIntervalDuration();

    RewardsInterval storage rewardsInterval = _rewardToInterval[reward];
    RewardsPerToken storage rewardsPerToken = rewardToRPT[reward];

    // A new rewards program cannot be set if one is running
    if (block.timestamp.toUint32() >= rewardsInterval.start && block.timestamp.toUint32() <= rewardsInterval.end) revert IntervalInProgress();

    // A new rewards program cannot be set if one is scheduled to run in the future
    if (rewardsInterval.start > block.timestamp) revert IntervalScheduled();

    // Update the rewards per token so that we don't lose any rewards
    _updateRewardsPerToken(reward);

    // Calculate fees
    uint256 frontendFeeTaken = totalRewards.mulWadDown(frontendFee);
    uint256 protocolFeeTaken = totalRewards.mulWadDown(WRAPPED_VAULT_FACTORY.protocolFee());

    // Make fees available for claiming
    rewardToClaimantToFees[reward][frontendFeeRecipient] += frontendFeeTaken;
    rewardToClaimantToFees[reward][WRAPPED_VAULT_FACTORY.protocolFeeRecipient()] += protocolFeeTaken;

    // Calculate the rate
    uint256 rate = (totalRewards - frontendFeeTaken - protocolFeeTaken) / (end - start);

    if (rate == 0) revert NoZeroRateAllowed();
    totalRewards = rate * (end - start) + frontendFeeTaken + protocolFeeTaken;

    rewardsInterval.start = start.toUint32();
    rewardsInterval.end = end.toUint32();
    rewardsInterval.rate = rate.toUint96();

    // If setting up a new rewards program, the rewardsPerToken.accumulated is used and built upon
    // New rewards start accumulating from the new rewards program start
    // Any unaccounted rewards from last program can still be added to the user rewards
    // Any unclaimed rewards can still be claimed
    rewardsPerToken.lastUpdated = start.toUint32();

    emit RewardsSet(reward, rewardsInterval.start, rewardsInterval.end, rate, (rate * (end - start)), protocolFeeTaken, frontendFeeTaken);

    _pullReward(reward, totalRewards);
}
```

We can see that there is no check to ensure that `start >= block.timestamp`. If reward interval being set has already started then those reward tokens from that forgone period will be **permanently stuck in the vault**

Note that that is not be mixed up with this check in the function:
```
// A new rewards program cannot be set if one is scheduled to run in the future
if (rewardsInterval.start > block.timestamp) revert IntervalScheduled();
```
That line checks if there is an existing reward interval and its not checking the `start` parameter in the function.

### Likelihood
This is **not an admin error** as there are multiple senarios which could result in `start` being < block.timestamp.

First senario is the admin could have set the reward interval to start soon, but due to network congestion in the Ethereum blockchain, the transaction ends up getting processed much later in a future block. 
  * Hence, the reward interval may have already started and those rewards will be stuck forever in the vault as there is **no recover function**.

Second senario is a chain re-org could have occurred and the block.timestamp of blocks could have changed (or the transaction was moved into a diff block).

### Impact
There seems to be no recover function in the wrapped vault **so those rewards lost will be stuck there forever**. (The refundRewardsInterval function doesn't help as it can't be called after the interval has started, which is the case for this bug)

### Recommendation
Require that start >= block.timestamp.

----

## [M-05] Rewards in WrappedVault could be lost due to `internalWithdrawDepositAndClaimCollateral` not updating all variables properly

### Vulnerability Details

Taking a look at `internalWithdrawDepositAndClaimCollateral` from `LendImpl.sol`:
```solidity
function internalWithdrawDepositAndClaimCollateral(
    IDahlia.MarketId id,
    IDahlia.Market storage market,
    IDahlia.UserPosition storage ownerPosition,
    address owner,
    address receiver
) internal returns (uint256 lendAssets, uint256 collateralAssets) {
      uint256 shares = ownerPosition.lendShares;
      require(shares > 0, Errors.ZeroAssets());
      uint256 totalCollateralAssets = market.totalCollateralAssets;
      uint256 totalLendAssets = market.totalLendAssets;
      uint256 totalLendShares = market.totalLendShares;

      // calculate owner assets based on liquidity in the market
      lendAssets = shares.toAssetsDown(totalLendAssets - market.totalBorrowAssets, totalLendShares);
      // Calculate owed collateral based on lendPrincipalAssets
      collateralAssets = (ownerPosition.lendPrincipalAssets * totalCollateralAssets) / market.totalLendPrincipalAssets;

      market.vault.burnShares(owner, ownerPosition.lendPrincipalAssets);
      ownerPosition.lendShares = 0;
-->   ownerPosition.lendPrincipalAssets = 0;
      market.totalLendShares = totalLendShares - shares;
      market.totalLendAssets = totalLendAssets - lendAssets;

      emit IDahlia.WithdrawDepositAndClaimCollateral(id, msg.sender, receiver, owner, lendAssets, collateralAssets, shares);
}
```

We can see that `ownerPosition.lendPrincipalAssets = 0` runs but `market.totalLendPrincipalAssets` **remains the same**. This breaks the important condition that `market.totalLendPrincipalAssets` = sum of all `ownerPosition.lendPrincipalAssets`.

The reason `market.totalLendPrincipalAssets` must be equal to the sum is because WrappedVault constantly accounts for the fraction by dividing by `market.totalLendPrincipalAssets`. Then for each individual user the value is **multiplied** by `ownerPosition.lendPrincipalAssets` to get the total rewards user should get.


### Impact
Some rewards in WrappedVault will not be distributed to the intended user and will be lost forever also. (It will be stuck in the vault)

Suppose there are 2 users each lent out equal amounts. And:
  * `market.totalLendPrincipalAssets = 10 ether`
  * `Alice.lendPrincipalAssets = 5 ether`
  * `Bob.lendPrincipalAssets = 5 ether`

Suppose `Bob` calls `internalWithdrawDepositAndClaimCollateral` at `Time X`. Then Bob's `lendPrincipalAssets` is set to 0, while `market.totalLendPrincipalAssets` **remains the same**.

Sometime in the future at `Time Y` when Alice calls the function, she will receive less rewards from WrappedVault then she is supposed.
  * Lets say `Reward R` is the reward that is being distributed from `Time X` to `Time Y`. Then 50% of `R` will be lost as `R` will be divided by `market.totalLendPrincipalAssets` and multiplied by `Alice.lendPrincipalAssets` which is **half** the value of the divisor even though Alice is the **only** staker left in the vault
  
  * `Bob` also cant "safe" the stuck reward from the vault because `Bob.lendPrincipalAssets` is already 0 

### Recommendation
Subtract to `market.totalLendPrincipalAssets` as well. 

(`market.totalCollateralAssets` should be subtracted by `collateralAssets` as well so that `collateralAssets` can be calculated properly since we are now updating `market.totalLendPrincipalAssets`).
