# Juicebox Audit Findings

In December of 2024, I participated in Juicebox V4's audit contest on Cantina securing [**1st place 🏆**](https://cantina.xyz/competitions/8d7bdfb9-cf19-4294-95d0-763af5d425b4/leaderboard) with 6 High Severity and 4 Medium Severity vulnerabilities.

## Table of contents
| Severity | Title |
|:--------:|-------|
| **High** | [[H-01] Attacker can exploit re-entrancy to retain ownership of clothing item even while their Banny is wearing it](#h-01-attacker-can-exploit-re-entrancy-to-retain-ownership-of-clothing-item-even-while-their-banny-is-wearing-it) |
| **High** | [[H-02] User can take back collateral without paying borrowed amount (and also steal the source fee as well)](#h-02-user-can-take-back-collateral-without-paying-borrowed-amount-and-also-steal-the-source-fee-as-well)
| **High** | [[H-03] Previous wearer's `_attachedWorldIdOf` not reset to 0 could cause issues](#h-03-previous-wearers-_attachedworldidof-not-reset-to-0-could-cause-issues) |
| **High** | [[H-04] Can exploit re-entrancy to mint more tokens in `JBController.sol`](#h-04-can-exploit-re-entrancy-to-mint-more-tokens-in-jbcontrollersol) |
| **High** | [[H-05] Revnet's `afterCashOutRecordedWith` hook does not give approval to feeTerminal causing permanent revert](#h-05-revnets-aftercashoutrecordedwith-hook-does-not-give-approval-to-feeterminal-causing-permanent-revert) |
| **High** | [[H-06] Malicious user can "duplicate" loans in REVLoans](#h-06-malicious-user-can-duplicate-loans-in-revloans) |
| **Medium** | [[M-01] Other users can frontrun to leech on victim's `toRemote` and cause victim to pay higher fee](#m-01-other-users-can-frontrun-to-leech-on-victims-toremote-and-cause-victim-to-pay-higher-fee) |
| **Medium** | [[M-02] Revnet does not handle converting existing juicebox projects into revnets properly in some situations](#m-02-revnet-does-not-handle-converting-existing-juicebox-projects-into-revnets-properly-in-some-situations) |
| **Medium** | [[M-03] `toRemote` shouldn't be ran if `emergencyHatch` is set to true](#m-03-toremote-shouldnt-be-ran-if-emergencyhatch-is-set-to-true) |
| **Medium** | [[M-04] User might end up getting funds stuck for 14 days in `JBSucker.sol`](#m-04-user-might-end-up-getting-funds-stuck-for-14-days-in-jbsuckersol) |

----

## [H-01] Attacker can exploit re-entrancy to retain ownership of clothing item even while their Banny is wearing it

### Summary
When trying to dress their banny, users can call `decorateBannyWith` which calls the internal function `_decorateBannyWithOutfits`. During the function, ERC721s are transferred back to the user and the user can make use of the callback function onERC721Received to carry out re-entrancy.
```solidity
function _decorateBannyWithOutfits(address hook, uint256 nakedBannyId, uint256[] memory outfitIds) internal {
    ....

    // Iterate through each outfit, transfering them in and adding them to the banny if needed, while transfering
    // out and removing old outfits no longer being worn.
    for (uint256 i; i < outfitIds.length; i++) {
        // Set the outfit ID being iterated on.
        uint256 outfitId = outfitIds[i];

        // Check if the call is being made either by the outfit's owner or the owner of the naked banny currently
        // wearing it.
        if (
            _msgSender() != IERC721(hook).ownerOf(outfitId)
1.)--->         && _msgSender() != IERC721(hook).ownerOf(wearerOf(hook, outfitId))
        ) {
            revert Banny721TokenUriResolver_UnauthorizedOutfit();
        }

        ....

        if (outfitProductCategory == _HEAD_TOP_CATEGORY) {
            hasHeadTop = true;
        } else if (outfitProductCategory == _SUIT_CATEGORY) {
            hasSuit = true;
        } else if (
            (
                outfitProductCategory == _GLASSES_CATEGORY || outfitProductCategory == _MOUTH_CATEGORY
                    || outfitProductCategory == _HEADTOP_CATEGORY
            ) && hasHeadTop
        ) {
            revert Banny721TokenUriResolver_HeadAlreadyAdded();
        } else if (
            (outfitProductCategory == _SUIT_TOP_CATEGORY || outfitProductCategory == _SUIT_BOTTOM_CATEGORY)
                && hasSuit
        ) {
            revert Banny721TokenUriResolver_SuitAlreadyAdded();
        }

        // Remove all previous assets up to and including the current category being iterated on.
        while (previousOutfitProductCategory <= outfitProductCategory && previousOutfitProductCategory != 0) {
            if (previousOutfitId != outfitId) {
                // Transfer the previous outfit to the owner of the banny.
                // slither-disable-next-line reentrancy-no-eth
                _transferFrom({hook: hook, from: address(this), to: _msgSender(), assetId: previousOutfitId});
            }

            if (++previousOutfitIndex < previousOutfitIds.length) {
                // set the next previous outfit.
                previousOutfitId = previousOutfitIds[previousOutfitIndex];
                // Get the next previous outfit.
                previousOutfitProductCategory = _productOfTokenId({hook: hook, tokenId: previousOutfitId}).category;
            } else {
                previousOutfitId = 0;
                previousOutfitProductCategory = 0;
            }
        }

        // If the outfit is not already being worn by the banny, transfer it to this contract.
        if (wearerOf({hook: hook, outfitId: outfitId}) != nakedBannyId) {
            // Store the banny that's in the world.
            _wearerOf[hook][outfitId] = nakedBannyId;

            // Transfer the outfit to this contract.
            // slither-disable-next-line reentrancy-no-eth
            _transferFrom({hook: hook, from: _msgSender(), to: address(this), assetId: outfitId});
        }

        // Keep a reference to the last outfit's category.
        lastAssetCategory = outfitProductCategory;
    }

    // Remove and transfer out any remaining assets no longer being worn.
    while (previousOutfitId != 0) {
        // Transfer the previous world to the owner of the banny.
        // slither-disable-next-line reentrancy-no-eth
        _transferFrom({hook: hook, from: address(this), to: _msgSender(), assetId: previousOutfitId});

        if (++previousOutfitIndex < previousOutfitIds.length) {
            // remove previous product.
            previousOutfitId = previousOutfitIds[previousOutfitIndex];
        } else {
            previousOutfitId = 0;
        }
    }

    // Store the outfits.
    _attachedOutfitIdsOf[hook][nakedBannyId] = outfitIds;
}
```

### Sequence of exploit
This is how an user can exploit re-entrancy via the 721 callback in order to cheat the system and maintain ownership of the clothing item while still wearing them.

1. Alice has a Banny with the following clothing worn: (sorted in ascending category order js as the function requires)
    1. item index 1 (from `_GLASSES_CATEGORY`)
    2. item index 2 (from `_HAND_CATEGORY`)
2. Both item 1 and item 2 are in ownership of the protocol since Alice has to transfer them to the contract when Banny is wearing them
3. Alice calls `decorateBannyWith` to re-dress Banny with clothing items:
    1. item index 1 (from `_GLASSES_CATEGORY`)
    2. item index 3 (from `_SUIT_CATEGORY`)
    * Even though Alice isnt the owner of item index 1 (that glasses) anymore this can still be done due to line `1.)` marked out in the code snippet pasted above (which exists so that some pieces of current clothing can be re-worn when the owner decides to re-dress)
4. As expected, item index 1 doesn't get transferred back to Alice as `if (previousOutfitId != outfitId)` will not hold true. Becoz the new set of clothing continues to include it in the outfit.
5. Item index 2 however gets transferred back to the user as it is no longer in the new set of clothing.
6. In the onERC721Received in Alice's contract triggered by the transfer of item index 2
    * Alice commits re-entrancy by calling `decorateBannyWith` with just item index 2 in the outfitId array.
7. Since in the original function `_attachedOutfitIdsOf[hook][nakedBannyId] = outfitIds;` has not ran yet, the current outfits worn by Banny will be the original set: item index 1 and item index 2.
8. The contract transfers item index 1 (the glasses) **back to Alice** and item index 2 (the hand) isn't moved(since it is both in the previous and new outfitID array).
9. The re-entrancy ends and skipping back to the **original trace**, `_attachedOutfitIdsOf[hook][nakedBannyId] = outfitIds;` runs.

So the last line running will set the outfit of the Banny to **item index 1 (glasses) and item index 3 (suit)**. However, **Alice still remains the owner** of item index 1, breaking the logic of the banny-looks protocol where the item must be in ownership of the contract if it is being worn.

Now, any malicious users can carry out this exploit to maintain ownership of a currently worn clothing and do whatever they want with the 721 still in their ownership (like transferring to others etc) even when their Banny is currently wearing it.

### Recommendation
Add a `nonReentrant` modifier to `decorateBannyWith`. This will fix the issue.

----

## [H-02] User can take back collateral without paying borrowed amount (and also steal the source fee as well)

### Summary
When repaying loans in `REVLoans.sol`, users are required to pay the amount borrowed (as well as the source fee) back to the source terminal of the REV project that they took a loan from.

However, there is a vulnerability that allows users to create their own REV project with their own malicious terminal and steal the borrowed amount back (+source fee) when they are repaying a loan taken **from a real** REV project belonging to the honest victim.

In `_repayLoan`, we can see that if you send more amount than required, it will be refunded to you. Suppose the borrowed token is ETH(`JB.NATIVE_TOKEN`) then I can get a `receive()` callback. Using this callback from the ETH transfer, I can take away the borrowed amount that I send back + the source fee while making the contract still think that I paid.
```solidity
function _repayLoan(
    uint256 loanId,
    REVLoan storage loan,
    uint256 borrowAmount,
    uint256 collateralAmountToReturn,
    address payable beneficiary
)
    internal
    returns (uint256, REVLoan memory)
{
    // Keep a reference to the fee that'll be taken.
    uint256 sourceFeeAmount = _determineSourceFeeAmount(loan, borrowAmount);

    // If the amount being paid is greater than the loan's amount, return extra to the payer.
    // amount is msg.value if token == JBConstants.NATIVE_TOKEN
    if (borrowAmount > loan.amount + sourceFeeAmount) {
-->     _transferFrom({
            from: address(this),
            to: payable(_msgSender()),
            token: loan.source.token,
            amount: borrowAmount - sourceFeeAmount - loan.amount
        });

        // Set the amount as the amount that can be paid off.
        borrowAmount = sourceFeeAmount + loan.amount;
    }
    .....
--> if (borrowAmount - sourceFeeAmount == loan.amount && collateralAmountToReturn == loan.collateral) {
        // Borrow in.
        _adjust({
            loan: loan,
            revnetId: revnetId,
            newBorrowAmount: 0,
            newCollateralAmount: 0,
            sourceFeeAmount: sourceFeeAmount,
            beneficiary: beneficiary
        });
        ....
    } else {
        ....
    }
    ....
}
```
After subtracting away the extra amount refunded to me, you can see that the code's `borrowAmount` variable will still be set to `sourceFeeAmount + loan.amount`. Hence, if I find a way to remove `sourceFeeAmount + loan.amount` from the contract during my `receive()` callback, the protocol will assume I paid it as this statement `if (borrowAmount - sourceFeeAmount == loan.amount && collateralAmountToReturn == loan.collateral)` will be true and the protocol will release the full collateral back to me.

It also won't revert due to the protocol's balance not having `sourceFeeAmount + loan.amount` as you can see in `_adjust`:
  * The part that sends the terminal back the borrowed amount uses `_removeFrom` to do so.
      * `_removeFrom` uses a `try` to attempt the call, so when that fails due to insufficient balance the catch (which is empty) will prevent it from reverting
  * As for stealing the source fee, the part that sends the terminal the source fee is at the bottom of `_adjust`, it simply attempts to transfer `_balanceOf(loan.source.token)` to the terminal and not strictly the `sourceFeeAmount` itself. So there will be no reverts.
        
### Sequence explanation
I will now explain that main part, which is how to take `sourceFeeAmount + loan.amount` in the receive() callback

1. Suppose I have a real loan from a real REV project belonging to victim
2. I will now create a fake REV project for myself (register with REVDeployer etc) with terminal set to a terminal that I own
3. Then I will take a 1 wei loan on my own project
4. Now, I intend to repay my real loan from the real REV project belonging to victim
5. I call `repayLoan` with slightly more ETH than needed, triggering the refund.
6. In the `receive()` callback, I proceed to repay my 1 wei loan on my own REV project using `repayLoan` as well.
7. So, calling `repayLoan` during my `receive()` callback will lead me to `_adjust` and at the end of it, the code simply transfers `_balanceOf(loan.source.token)` to this fake loan's source terminal (which is my terminal)
8. Hence, I am able to get back **all the ETH** (`sourceFeeAmount + loan.amount`)
9. When the re-entrancy ends, and the original trace continues, it will not revert due to what I have explained in the bottom few lines of my summary section.
10. My collateral will also then be released.

### Recommendation
Add `nonReentrant` guard to `repayLoan`.

---

## [H-03] Previous wearer's `_attachedWorldIdOf` not reset to 0 could cause issues

### Summary
In `Banny721TokenUriResolver.sol`'s internal function `_decorateBannyWithWorld`:
```solidity
function _decorateBannyWithWorld(address hook, uint256 nakedBannyId, uint256 worldId) internal {
    // Keep a reference to the previous world attached.
    uint256 previousWorldId = _attachedWorldIdOf[hook][nakedBannyId];

    // If the world is changing, add the lateset world and transfer the old one back to the owner.
    if (worldId != previousWorldId) {
        // Add the world if needed.
        if (worldId != 0) {
            // Check if the call is being made by the world's owner, or the owner of a naked banny using it.
            if (
                _msgSender() != IERC721(hook).ownerOf(worldId)
1.)--->             && _msgSender() != IERC721(hook).ownerOf(userOf(hook, worldId))
            ) {
                revert Banny721TokenUriResolver_UnauthorizedWorld();
            }
            ....
            // Store the world for the banny.
2.)--->     _attachedWorldIdOf[hook][nakedBannyId] = worldId;

            // Store the banny that's in the world.
            _userOf[hook][worldId] = nakedBannyId;
            ....
        } else {
            ....
        }
        // If there's a previous world, transfer it back to the owner.
        if (previousWorldId != 0) {
            // Transfer the previous world to the owner of the banny.
3.)--->     _transferFrom({hook: hook, from: address(this), to: _msgSender(), assetId: previousWorldId});
        }
    }
}
```
As shown by the line `1.)` marked out above, it serves to allow switching, meaning if the owner owns both Banny X and Banny Y, suppose world 1 is currently at Banny X then the owner can switch it to Banny Y.(as denoted by line `1.)` since `userOf(hook, worldId)` will return Banny X's id and owner is the `ownerOf` Banny X).

However, as shown in line `2.)`, only `_attachedWorldIdOf[hook][Banny Y]` will be updated. **The previous banny that wears it will have their array `_attachedWorldIdOf[hook][Banny X]` still set to `worldId`**.

This seems harmless at first sight as parts of the code that uses `_attachedWorldIdOf[hook][Banny X]` cross checks with the `_userOf` (like in functions `assetIdsOf` and function `userOf`)

However there are 2 ways that could lead to issues.

### Issue 1
1. Account Owner owns both Banny X and Banny Y
2. Banny X is wearing world 1
3. Account switches world 1 to Banny Y
    * Banny X's `_attachedWorldIdOf` will still be set to world 1 due to the bug of not setting it to zero
4. User makes Banny X wear a new world: world 2
    * Since `previousWorldId = _attachedWorldIdOf[hook][nakedBannyId]`, Banny X's previousWorld will **still** be world 1.
    * **Then the protocol transfers ownership of world 1 back to owner even though Banny Y is still wearing it** (line `3.)` that I marked in the code snippet i pasted above)

This results in the owner having ownership of world 1, even though Banny Y is wearing it.

### Issue 2
1. Account Owner owns both Banny X and Banny Y
2. Banny X is wearing world 1
3. Account switches world 1 to Banny Y
    * Banny X's `_attachedWorldIdOf` will still be set to world 1 due to the bug of not setting it to zero
4. For personal reasons, User decides to switch world 1 back to Banny X.
    * Now the issue occurs because of the line `previousWorldId = _attachedWorldIdOf[hook][nakedBannyId]`
    * So Banny X's previousWorldId will still be world 1
    * This causes `if (worldId != previousWorldId)` to be false, so nothing changes in `_decorateBannyWithWorld`, meaning `_userOf[hook][world 1]` **does not change back** to Banny X.
    * And hence, the protocol will still wrongly document it as Banny Y that is still wearing world 1

### Recommendation
If the world has a previous wearer, set its' previous wearers' `_attachedWorldIdOf` to 0.
```diff
function _decorateBannyWithWorld(address hook, uint256 nakedBannyId, uint256 worldId) internal {
    ....
    if (worldId != previousWorldId) {
        // Add the world if needed.
        if (worldId != 0) {
            ....
            
            // Store the world for the banny.
+           if(userOf(hook, worldId) != 0) _attachedWorldIdOf[hook][userOf(hook, worldId)] = 0;            
            _attachedWorldIdOf[hook][nakedBannyId] = worldId;

            // Store the banny that's in the world.
            _userOf[hook][worldId] = nakedBannyId;
            
            // Transfer the world to this contract.
            _transferFrom({hook: hook, from: _msgSender(), to: address(this), assetId: worldId});
        } else {
            _attachedWorldIdOf[hook][nakedBannyId] = 0;
        }
        ....
    }
}
```

----

## [H-04] Can exploit re-entrancy to mint more tokens in JBController.sol

### Summary
In controller's `_sendReservedTokensToSplitsOf`, we can see that `pendingReservedTokenBalanceOf[projectId] = 0;` while project tokens to the split hasn't been minted.

Looking at this function:
```solidity
function totalTokenSupplyWithReservedTokensOf(uint256 projectId) external view override returns (uint256) {
    // Add the reserved tokens to the total supply.
    return TOKENS.totalSupplyOf(projectId) + pendingReservedTokenBalanceOf[projectId];
}
```

This means that until each split's token has been minted individually in the for loop, `totalTokenSupplyWithReservedTokensOf` will display a lower amount.

So, if we can do a re-entrancy to cash out at this point, we can get more tokens since, the total supply is lower than it should be, **giving the attacker a temporarily better rate**.

In `_sendReservedTokensToSplitGroupOf` during the for loop, we can see that there are calls to `TOKENS.mintFor({holder: beneficiary, projectId: projectId, count: splitTokenCount});`. 

### Impact
Since the for loop isn't finished, a callback from mintFor will mean that total supply will still be lower than what it should be, giving the attacker a better rate when they cash out during the re-entrancy.

mintFor can give the attacker a callback especially if the project token used is a 721, which is quite commonly used in the juicebox repo.

### Recommendation
Only set `pendingReservedTokenBalanceOf[projectId] = 0;` at the end of the function.

----

## [H-05] Revnet's `afterCashOutRecordedWith` hook does not give approval to feeTerminal causing permanent revert

### Summary

In REVDeployer.sol's `afterCashOutRecordedWith` hook call:
```solidity
  function afterCashOutRecordedWith(JBAfterCashOutRecordedContext calldata context) external payable {
      // Only the revnet's payment terminals can access this function.
      if (!DIRECTORY.isTerminalOf(context.projectId, IJBTerminal(msg.sender))) {
          revert REVDeployer_Unauthorized();
      }

      // Parse the metadata forwarded from the data hook to get the fee terminal.
      // See `beforeCashOutRecordedWith(…)`.
      (IJBTerminal feeTerminal) = abi.decode(context.hookMetadata, (IJBTerminal));

      // Determine how much to pay in `msg.value` (in the native currency).
1.)-> uint256 payValue = context.forwardedAmount.token == JBConstants.NATIVE_TOKEN ? context.forwardedAmount.value : 0;

      // Pay the fee.
      // slither-disable-next-line arbitrary-send-eth,unused-return
2.)-> try feeTerminal.pay{value: payValue}({
          projectId: FEE_REVNET_ID,
          token: context.forwardedAmount.token,
          amount: context.forwardedAmount.value,
          beneficiary: context.holder,
          minReturnedTokens: 0,
          memo: "",
          metadata: bytes(abi.encodePacked(context.projectId))
      }) {} catch (bytes memory) {
          // If the fee can't be processed, return the funds to the project.
          // slither-disable-next-line arbitrary-send-eth
          IJBTerminal(msg.sender).addToBalanceOf{value: payValue}({
              projectId: context.projectId,
              token: context.forwardedAmount.token,
              amount: context.forwardedAmount.value,
              shouldReturnHeldFees: false,
              memo: "",
              metadata: bytes(abi.encodePacked(FEE_REVNET_ID))
          });
      }
  }
```

From the line marked with `1.)` to the line marked with `2.)` we can see that revnet does not give allowance to feeTerminal if the token isn't the native token.

The revnet's `afterCashOutRecordedWith` hook are called by terminals for example in JBMultiTerminal.sol:
```solidity
  function _fulfillCashOutHookSpecificationsFor(
      ....
  )
      internal
      returns (uint256 amountEligibleForFees)
  {
      ....

      for (uint256 i; i < specifications.length; i++) {
          ....
          
          // Trigger any inherited pre-transfer logic.
          // Keep a reference to the amount that'll be paid as a `msg.value`.
          // slither-disable-next-line reentrancy-events
3.)-->    uint256 payValue = _beforeTransferTo({
              to: address(specification.hook),
              token: beneficiaryReclaimAmount.token,
              amount: specification.amount
          });

          // Fulfill the specification.
          // slither-disable-next-line reentrancy-events
          specification.hook.afterCashOutRecordedWith{value: payValue}(context);
          
          .....
      }
  }
```
Terminals give allowance to the revnet (thru the line `3.)`) using the function `_beforeTransferTo` if the token isnt the native token.

However, the revnet doesn't give the appriopriate allowance to the feeTerminal.

### Impact
**The fee terminal ends up not receiving any fee.** As it uses a try catch, when feeTerminal.pay fails, the catch will run:
```solidity
}) {} catch (bytes memory) {
    // If the fee can't be processed, return the funds to the project.
    // slither-disable-next-line arbitrary-send-eth
    IJBTerminal(msg.sender).addToBalanceOf{value: payValue}({
        projectId: context.projectId,
        token: context.forwardedAmount.token,
        amount: context.forwardedAmount.value,
        shouldReturnHeldFees: false,
        memo: "",
        metadata: bytes(abi.encodePacked(FEE_REVNET_ID))
    });
}
```
The catch attempts to send the funds intended for fees back to msg.sender, which is the original terminal calling the hook.

However, `addToBalanceOf` will revert as well, as it uses `_acceptFundsFor` which calls `_transferFrom` which ends up calling `PERMIT2.transferFrom`, which will revert as there was no allowance from revnet to original terminal as well.

### Recommendation
Inside revnet, when dealing with non-native tokens, first transfer to contract the tokens that the original terminal has given you allowance for.

Then before feeTerminal.pay, give allowance to feeTerminal to take `amount`.

If try fails, inside catch, revoke allowance to feeTerminal and give allowance to original terminal before calling `addToBalanceOf`.

----

## [H-06] Malicious user can "duplicate" loans in REVLoans

### Summary

Suppose currently I have a loan with: (X amount, Y collateral). There's a way that I can exploit to duplicate it and basically make the protocol treat it as I have 2 of such loans (when i only have one).

Meaning, I can pay `2 * X` amounts of tokens, to get back `2 * Y` amounts of collateral(collateral is basically minting the project's token, so it **does not** require the REV's contract balance to have it)

This can allow users to easily steal money as throughout different stages/rulesets, **the project can have very different `project token : asset token` ratio**. So if in an earlier stage the user has a normal (X amount, Y collateral) loan, and in later stages, the ratio improves making collateral tokens worth more, the user can exploit this doubling bug to pay `2 * X` amounts to get back `2 * Y`.
  * Note that this is very different from just creating a new (X amount, Y collateral) loan, becoz as mentioned, the ratio of the project has changed and the collateral is now worth more. (liquidation is not involved here as the collateral is the one that has been inflated)

I will now paste the few involved functions so that I can label a few important lines that I will bring up when explaining the sequence:
```solidity
function repayLoan(
    uint256 loanId,
    uint256 borrowAmount,
    uint256 collateralAmountToReturn,
    address payable beneficiary,
    JBSingleAllowance calldata allowance
)
    external
    payable
    override
    returns (uint256, REVLoan memory)
{
    // Make sure only the loan's owner can manage it.
    if (_ownerOf(loanId) != _msgSender()) revert REVLoans_Unauthorized(_msgSender(), _ownerOf(loanId));

    // Keep a reference to the fee being iterated on.
    REVLoan storage loan = _loanOf[loanId];

    if (collateralAmountToReturn > loan.collateral) {
        revert REVLoans_CollateralExceedsLoan(collateralAmountToReturn, loan.collateral);
    }

    // Accept the funds that'll be used to pay off loans.
    borrowAmount = _acceptFundsFor({token: loan.source.token, amount: borrowAmount, allowance: allowance});

    return _repayLoan({
        loanId: loanId,
        loan: loan,
        borrowAmount: borrowAmount,
        collateralAmountToReturn: collateralAmountToReturn,
        beneficiary: beneficiary
    });
}
function _repayLoan(
    uint256 loanId,
    REVLoan storage loan,
    uint256 borrowAmount,
    uint256 collateralAmountToReturn,
    address payable beneficiary
)
    internal
    returns (uint256, REVLoan memory)
{
    // Keep a reference to the fee that'll be taken.
    uint256 sourceFeeAmount = _determineSourceFeeAmount(loan, borrowAmount);

    // If the amount being paid is greater than the loan's amount, return extra to the payer.
    // amount is msg.value if token == JBConstants.NATIVE_TOKEN
    if (borrowAmount > loan.amount + sourceFeeAmount) {
        _transferFrom({
            from: address(this),
            to: payable(_msgSender()),
            token: loan.source.token,
            amount: borrowAmount - sourceFeeAmount - loan.amount
        });

        // Set the amount as the amount that can be paid off.
        borrowAmount = sourceFeeAmount + loan.amount;
    }

    // Get a reference to the revnet ID.
    uint256 revnetId = revnetIdOfLoanWith(loanId);

    // Burn the original loan.
    _burn(loanId);

    // If the loan will carry no more amount or collateral, store its changes directly.
    // slither-disable-next-line incorrect-equality
    if (borrowAmount - sourceFeeAmount == loan.amount && collateralAmountToReturn == loan.collateral) {
        // Borrow in.
        _adjust({
            loan: loan,
            revnetId: revnetId,
            newBorrowAmount: 0,
            newCollateralAmount: 0,
            sourceFeeAmount: sourceFeeAmount,
            beneficiary: beneficiary
        });

        emit RepayLoan({
            loanId: loanId,
            revnetId: revnetId,
            paidOffLoanId: loanId,
            loan: loan,
            paidOffLoan: loan,
            borrowAmount: borrowAmount,
            sourceFeeAmount: sourceFeeAmount,
            collateralAmountToReturn: collateralAmountToReturn,
            beneficiary: beneficiary,
            caller: _msgSender()
        });

        return (loanId, loan);
    } else {
        // Make a new loan with the remaining amount and collateral.
        // Get a reference to the replacement loan ID.
        uint256 paidOffLoanId = _generateLoanId({revnetId: revnetId, loanNumber: ++numberOfLoansFor[revnetId]});

        // Mint the replacement loan.
1.)-->  _mint({to: _msgSender(), tokenId: paidOffLoanId});

        // Get a reference to the loan being paid off.
        REVLoan storage paidOffLoan = _loanOf[paidOffLoanId];

        // Set the paid off loan's values the same as the original loan.
        paidOffLoan.amount = loan.amount;
        paidOffLoan.collateral = loan.collateral;
        paidOffLoan.createdAt = loan.createdAt;
        paidOffLoan.prepaidFeePercent = loan.prepaidFeePercent;
        paidOffLoan.prepaidDuration = loan.prepaidDuration;
        paidOffLoan.source = loan.source;

        // Borrow in.
        _adjust({
            loan: paidOffLoan,
            revnetId: revnetId,
            newBorrowAmount: paidOffLoan.amount - (borrowAmount - sourceFeeAmount),
            newCollateralAmount: paidOffLoan.collateral - collateralAmountToReturn,
            sourceFeeAmount: sourceFeeAmount,
            beneficiary: beneficiary
        });

        ...

        return (paidOffLoanId, paidOffLoan);
    }
}
function _adjust(
    REVLoan storage loan,
    uint256 revnetId,
    uint256 newBorrowAmount,
    uint256 newCollateralAmount,
    uint256 sourceFeeAmount,
    address payable beneficiary
)
    internal
{
    ...

    {
        // Get a reference to the accounting context for the source.
        JBAccountingContext memory accountingContext =
            loan.source.terminal.accountingContextForTokenOf({projectId: revnetId, token: loan.source.token});

        // Keep a reference to the pending auto issuance tokens.
        uint256 pendingAutoIssuanceTokens = revnetOwner.unrealizedAutoIssuanceAmountOf(revnetId);

        // Keep a reference to the current stage.
        JBRuleset memory currentStage = controller.RULESETS().currentOf(revnetId);

        // Keep a reference to the revnet's terminals.
        IJBTerminal[] memory terminals = directory.terminalsOf(revnetId);

        // If the borrowed amount is increasing or the collateral is changing, check that the loan will still be
        // properly collateralized.
        if (
            (newBorrowAmount > loan.amount || loan.collateral != newCollateralAmount)
                && _borrowableAmountFrom({
                    revnetId: revnetId,
                    collateralAmount: newCollateralAmount,
                    pendingAutoIssuanceTokens: pendingAutoIssuanceTokens,
                    decimals: accountingContext.decimals,
                    currency: accountingContext.currency,
                    currentStage: currentStage,
                    terminals: terminals,
                    prices: controller.PRICES(),
                    tokens: controller.TOKENS()
                }) < newBorrowAmount
        ) revert REVLoans_NotEnoughCollateral();
    }

    // Add to the loan if needed...
    if (newBorrowAmount > loan.amount) {
        // Keep a reference to the fee terminal.
        IJBTerminal feeTerminal = directory.primaryTerminalOf(REV_ID, loan.source.token);

        // Add the new amount to the loan.
        _addTo({
            loan: loan,
            revnetId: revnetId,
            borrowAmount: newBorrowAmount - loan.amount,
            sourceFeeAmount: sourceFeeAmount,
            feeTerminal: feeTerminal,
            beneficiary: beneficiary
        });
        // ... or pay off the loan if needed.
    } else if (loan.amount > newBorrowAmount) {
        _removeFrom({loan: loan, revnetId: revnetId, borrowAmount: loan.amount - newBorrowAmount});
    }

    // Add collateral if needed...
    if (newCollateralAmount > loan.collateral) {
        _addCollateralTo({revnetId: revnetId, amount: newCollateralAmount - loan.collateral, controller: controller});
        // ... or return collateral if needed.
    } else if (loan.collateral > newCollateralAmount) {
        _returnCollateralFrom({
            revnetId: revnetId,
            collateralAmount: loan.collateral - newCollateralAmount,
            beneficiary: beneficiary,
            controller: controller
        });
    }

    // Get a reference to the amount remaining in this contract.
    uint256 balance = _balanceOf(loan.source.token);

    // The amount remaining in the contract should be the source fee.
    if (balance > 0) {
        // Increase the allowance for the beneficiary.
        uint256 payValue =
            _beforeTransferTo({to: address(loan.source.terminal), token: loan.source.token, amount: balance});

        // Pay the fee.
        // slither-disable-next-line unused-return
        try loan.source.terminal.pay{value: payValue}({
            projectId: revnetId,
            token: loan.source.token,
            amount: balance,
            beneficiary: beneficiary,
            minReturnedTokens: 0,
            memo: "Fee from loan",
            metadata: bytes(abi.encodePacked(REV_ID))
        }) {} catch (bytes memory) {}
    }

    // Store the loans updated values.
    loan.amount = uint112(newBorrowAmount);
    loan.collateral = uint112(newCollateralAmount);
}
function _returnCollateralFrom(
    uint256 revnetId,
    uint256 collateralAmount,
    address payable beneficiary,
    IJBController controller
)
    internal
{
    // Decrement the total amount of collateral tokens.
    totalCollateralOf[revnetId] -= collateralAmount;

    // Mint the collateral tokens back to the loan payer.
    // slither-disable-next-line unused-return,calls-loop
    controller.mintTokensOf({
        projectId: revnetId,
        tokenCount: collateralAmount,
        beneficiary: beneficiary,
        memo: "Removing collateral from loan",
        useReservedPercent: false
    });
}
```

### Sequence explanation
1. I have a loan (X amount, Y collateral).
2. I call repayLoan, repaying all X amount(+source fee) and requesting for Y - 1 wei of collateral back.
3. Since I have 1 wei of collateral remaining, `_repayLoan` will mint a new loan for me (as shown in line `1.)`)
4. The parameters of the new loan will be set to the original ones (basically X and Y) and `_adjust` will be called with `newBorrowAmount = 0` and `newCollateralAmount = 1 wei`.
5. Inside `_adjust`, `_returnCollateralFrom` will be called.
6. `_returnCollateralFrom` will attempt to mint project tokens to me, if the project uses 721 tokens then I will be able to receive a callback.
7. In the callback, I will call `repayLoan` again (since previously in step 3, `_repayLoan` has minted a new one for me(which I will be the owner of) with original parameters)
  * Since the original trace hasn't reached the `loan.amount = uint112(newBorrowAmount); loan.collateral = uint112(newCollateralAmount);` part, I can basically take advantage of the loan **having its original parameters.**
8. Then in this `repayLoan` I can just repay the full X amount and request for the full Y amount of collateral.

### Impact
As shown in the sequence, I pay `2 * X` tokens back and REVLoans.sol uses the controller to mint `2 * Y - 1 wei` of collateral tokens for me. (Even though I only had 1 original X,Y loan)

Once again, this becomes a profit glitch that I can use on a loan which i had taken in an earlier stage given that the price of collateral tokens have now inflated possibly in the later stages/rulesets. (liquidation doesn't occur on this loan as its the collateral value being inflated)

### Recommendation
Shift the minting new revloan id(line `1.)` marked out in the pasted code above) to after `_adjust` is called. 

That way, if the user does not have ownership over the newly created loan until the **important line** at the end of `_adjust` runs: `loan.amount = uint112(newBorrowAmount); loan.collateral = uint112(newCollateralAmount);`. Then the user will not be able to create imaginary loans.


----
----

## [M-01] Other users can frontrun to leech on victim's `toRemote` and cause victim to pay higher fee

### Summary
In JBSucker.sol's toRemote:
```solidity
function toRemote(address token) external payable override {
    JBRemoteToken memory remoteToken = _remoteTokenFor[token];

    // Ensure that the amount being bridged exceeds the minimum bridge amount.
    if (_outboxOf[token].balance < remoteToken.minBridgeAmount) {
        revert JBSucker_QueueInsufficientSize(_outboxOf[token].balance, remoteToken.minBridgeAmount);
    }

    // Send the merkle root to the remote chain.
    _sendRoot({transportPayment: msg.value, token: token, remoteToken: remoteToken});
}
```
We can see that the whole outBox.balance is sent to the remote chain with the msg.sender calling toRemote barring the full cost of the fee. This does not cause extra losses for the victim for bridging optimism and arbitrium as both seem to charge standard fee. 

### Impact
However, for the ccip chain, **the fee increases as the amount bridged increases**. Since such bridging is meant for the victim to send msg.value that is slightly in excess and then get the refund (JBCCIPSucker.sol indeed does refund unused msg.value to the msg.sender). 

Hence, if malicious users see that a victim is calling toRemote and decide to all rush to call prepare() in order to leech on the victim's msg.value, the victim will get a lesser msg.value refund, causing loss.

If the victim however, decides to send a stricter msg.value to counter the leechers, but too many malicious leechers come in, then the whole transaction could revert due to fee exceeding msg.value, causing a delay in bridging for the victim.

### Evidence
The evidence that I found online about fee increasing when token amounts bridged increases can be found here: https://github.com/smartcontractkit/ccip/blob/c279cbb4ab57436b9c59c9321492e25f0aa30e80/contracts/src/v0.8/ccip/onRamp/EVM2EVMOnRamp.sol#L672

----

## [M-02] Revnet does not handle converting existing juicebox projects into revnets properly in some situations

### Summary
In REVDeployer.sol any owners of projects can call `deployFor`, which will subsequently call `_deployRevnetFor`.

This is meant to be compatible with both new projects as well as existing projects whom the user wishes to convert into a revnet.

This info can be shown from either the revnet docs **or the code itself**:
```solidity
  function _deployRevnetFor(
      uint256 revnetId,
      REVConfig calldata configuration,
      JBTerminalConfig[] calldata terminalConfigurations,
      REVBuybackHookConfig calldata buybackHookConfiguration,
      REVSuckerDeploymentConfig calldata suckerDeploymentConfiguration
  )
      internal
      returns (uint256)
  {
      ....

      if (revnetId == 0) {
          // If we're deploying a new revnet, launch a Juicebox project for it.
          .....
      } else {
          // If we're converting an existing Juicebox project into a revnet,
          // transfer the `JBProjects` NFT to this deployer.
          IERC721(PROJECTS).safeTransferFrom({from: PROJECTS.ownerOf(revnetId), to: address(this), tokenId: revnetId});

          // Launch the revnet rulesets for the pre-existing project.
          // slither-disable-next-line unused-return
          CONTROLLER.launchRulesetsFor({
              projectId: revnetId,
              rulesetConfigurations: rulesetConfigurations,
              terminalConfigurations: terminalConfigurations,
              memo: ""
          });
      }
      ....
      ....
  }
```
So as you can see from the code, the `else` statement part is responsible for converting existing Juicebox projects into revnets if the owner of the project wishes.

However, there is a compatibility issue as `CONTROLLER.launchRulesetsFor` reverts if the project has existing rulesets. Instead the code should have checked if the project already had existing rulesets, and if so opt to use `CONTROLLER.queueRulesetsOf` instead.

### Impact
Projects being converted might end up reverting the transaction as the code uses `launchRulesetsFor` even for projects with existing rulesets.

### Recommendation
In that else statement responsible for converting Juicebox projects into revnets:
```
else {
    If the project has no existing ruleset {
        Run the current code as per normal (using `CONTROLLER.launchRulesetsFor`)
        ....
    } else {
        Opt to use `CONTROLLER.queueRulesetsOf` instead
    }
}
```

----

## [M-03] `toRemote` shouldn't be ran if `emergencyHatch` is set to true

### Summary
```solidity
function toRemote(address token) external payable override {
    JBRemoteToken memory remoteToken = _remoteTokenFor[token];

    // Ensure that the amount being bridged exceeds the minimum bridge amount.
    if (_outboxOf[token].balance < remoteToken.minBridgeAmount) {
        revert JBSucker_QueueInsufficientSize(_outboxOf[token].balance, remoteToken.minBridgeAmount);
    }

    // Send the merkle root to the remote chain.
    _sendRoot({transportPayment: msg.value, token: token, remoteToken: remoteToken});
}
```

Should add a check that `_remoteTokenFor[terminalToken].emergencyHatch != true` before allowing the bridging to occur

`emergencyHatch` being enabled could mean that admin wants to stop allowing this particular token from being bridged, hence it is better to have it check and revert if that is the case

### Impact
Code might end up wrongly allowing token to get bridged even when it should no longer be allowed to.

### Recommendation
Check `_remoteTokenFor[terminalToken].emergencyHatch != true`

----

## [M-04] User might end up getting funds stuck for 14 days in `JBSucker.sol`

### Summary
In JBSucker.sol's `_validateForEmergencyExit`, we can see that this is the condition the code has in order to call it
```solidity
if (!_remoteTokenFor[terminalToken].emergencyHatch && state() != JBSuckerState.DEPRECATED) {
    revert JBSucker_TokenHasInvalidEmergencyHatchState(terminalToken);
}
```

However, instead of `state() != JBSuckerState.DEPRECATED`, it should be `state() != JBSuckerState.DEPRECATED && state() != JBSuckerState.SENDING_DISABLED`.

This is because when the `state() = JBSuckerState.SENDING_DISABLED` any tokens that the user had previously sent to the contract using `prepare(...)` before the state changed into SENDING_DISABLED **will already not be allowed to be bridged to remote chain anyways**. 

The difference between `SENDING_DISABLED` and `DEPRECIATED` **is only for receiving tokens from remote chain**. Hence, in the context of `_validateForEmergencyExit`, they should be treated no differently from `state() == DEPRECIATED` and should be allowed to exit.

### Impact
Now, users stuck in this senario will have to endure **an unnecessary lockup/DoS of 14 days** (as that is the time taken for SENDING_DISABLED to change to DEPRECIATED)

Getting funds stuck for 2 weeks is a **big opportunity cost especially since they could miss a ruleset cycle of a project** that they want to participate in.

### Recommedation
In `_validateForEmergencyExit` change the if condition to to prevent the unnecessary 14 day DoS:
```diff
- if (!_remoteTokenFor[terminalToken].emergencyHatch && state() != JBSuckerState.DEPRECATED) {
+ if (!_remoteTokenFor[terminalToken].emergencyHatch && state() != JBSuckerState.DEPRECATED && state() != JBSuckerState.SENDING_DISABLED) {
    revert JBSucker_TokenHasInvalidEmergencyHatchState(terminalToken);
  }
```
