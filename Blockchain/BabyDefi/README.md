## Writeup

Sandwich attack + Arbitrary mint

The public function sellSomeForFlag() can be used to launch a sandwich attack.

-  FlashLoan borrow N1Token
  - swap N1Token for Flagtoken in SimpleSwap
  - call sellSomeForFlag function
  - swap Flagtoken for N1Token
  - return FlashLoan

After this step, you will get about 514*1e18 N1Token.

There is a update delay in the deposit function:

```
	function deposit(address token,uint256 _amount) external {
        require(token == tokenAccept,"Fake Token.");
        PoolInfo memory poolInfo = poolInfos[token]; //old 
        updatePool(token);
        UserInfo storage user = userInfo[msg.sender];
        if (user.amount > 0) {
            uint256 pending = user.amount.mul(poolInfo.accRewardsPerToken).div(1e18).sub(user.rewardDebt);
            if (pending > 0) {
                IMintToken(flagToken).mint(msg.sender, pending);
            }
        }
        if (_amount > 0) {
            IERC20(token).safeTransferFrom(address(msg.sender), address(this), _amount);
            user.amount = user.amount.add(_amount);
        }
        user.rewardDebt = user.amount.mul(poolInfo.accRewardsPerToken).div(1e18); // wrong
        emit Deposit(msg.sender,_amount);
    }
```

So the user.rewardDebt is miscalculated.So a sufficient amount of Flagtoken can be obtained by doing the following.

- Deposit 1 N1Token.
- Wait for about 6 minutes to get enough pool.accRewardsPerToken.
- Deposit the rest of N1Token, and claimReward.



## Setup Environment

Thanks to chainflag for providing the environment. 

Set up the environment with [eta-challenge-base](https://github.com/chainflag/eth-challenge-base).

