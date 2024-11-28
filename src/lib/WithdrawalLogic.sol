// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { ForcedWithdrawalStatus } from "../types/ForcedWithdrawalStatus.sol";
import { ResetPeriod } from "../types/ResetPeriod.sol";

import { SharedLogic } from "./SharedLogic.sol";
import { EfficiencyLib } from "./EfficiencyLib.sol";
import { EventLib } from "./EventLib.sol";
import { IdLib } from "./IdLib.sol";

/**
 * @title WithdrawalLogic
 * @notice Inherited contract implementing internal functions with logic for processing
 * forced withdrawals, including initiation and the actual withdrawal, and for querying
 * for the forced withdrawal status for given resource locks.
 */
contract WithdrawalLogic is SharedLogic {
    using IdLib for uint256;
    using IdLib for ResetPeriod;
    using EfficiencyLib for uint256;
    using EventLib for uint256;

    // Storage scope for forced withdrawal activation times:
    // slot: keccak256(_FORCED_WITHDRAWAL_ACTIVATIONS_SCOPE ++ account ++ id) => activates.
    uint256 private constant _FORCED_WITHDRAWAL_ACTIVATIONS_SCOPE = 0x41d0e04b; // WHERE IS THIS COMING FROM?

    /**
     * @notice Internal function for initiating a forced withdrawal. Computes the withdrawable
     * timestamp by adding the current block timestamp to the reset period associated with the
     * resource lock, stores the sum, and emits a ForcedWithdrawalStatusUpdated event.
     * @param id                The ERC6909 token identifier of the resource lock.
     * @return withdrawableAt   The timestamp at which tokens become withdrawable.
     */
    function _enableForcedWithdrawal(uint256 id) internal returns (uint256 withdrawableAt) {
        // Skip overflow check as reset period is bounded.
        unchecked {
            // Derive the time at which the forced withdrawal is enabled.
            withdrawableAt = block.timestamp + id.toResetPeriod().toSeconds();
        }

        // Derive storage slot containing time withdrawal is enabled.
        uint256 cutoffTimeSlotLocation = _getCutoffTimeSlot(msg.sender, id);
        assembly ("memory-safe") {
            // Store the time at which the forced withdrawal is enabled.
            sstore(cutoffTimeSlotLocation, withdrawableAt)

            // WHY DO WE OVERRIDE A PREVIOUS FORCE WITHDRAWAL TIME WITH A LATER ONE? RATHER REVERT?
        }

        // AN ALLOCATOR NEEDS TO KEEP TRACK OF THE FORCE WITHDRAWAL STATE OF A USER PRIOR TO AN ALLOCATION.
        // THE ALLOCATOR ALSO NEEDS TO MAKE SURE THAT LOCK TIMES NEVER EXCEED THE RESET PERIOD OF A TOKEN.

        // SHOULD AN ONGOING FORCE WITHDRAWAL BLOCK NEW DEPOSITS OF THE USER TO THE UNDERLYING TOKEN?

        // emit the ForcedWithdrawalStatusUpdated event.
        id.emitForcedWithdrawalStatusUpdatedEvent(withdrawableAt);
    }

    /**
     * @notice Internal function for disabling a forced withdrawal. Reverts if the withdrawal
     * is already disabled, clears the withdrawable timestamp, and emits a
     * ForcedWithdrawalStatusUpdated event.
     * @param id The ERC6909 token identifier of the resource lock.
     * @return   Whether the forced withdrawal was successfully disabled.
     */
    function _disableForcedWithdrawal(uint256 id) internal returns (bool) {
        // Derive storage slot containing time withdrawal is enabled.
        uint256 cutoffTimeSlotLocation = _getCutoffTimeSlot(msg.sender, id);

        assembly ("memory-safe") {
            // Revert if withdrawal is already disabled.
            if iszero(sload(cutoffTimeSlotLocation)) {
                // revert ForcedWithdrawalAlreadyDisabled(msg.sender, id)
                mstore(0, 0xe632dbad)
                mstore(0x20, caller())
                mstore(0x40, id)
                revert(0x1c, 0x44)
            }

            // Clear the value for the stored time the withdrawal is enabled.
            sstore(cutoffTimeSlotLocation, 0)
        }

        // AN ALLOCATOR NEEDS TO KEEP TRACK OF THE FORCE WITHDRAWAL STATE OF A USER PRIOR TO AN ALLOCATION.
        // THE ALLOCATOR ALSO NEEDS TO MAKE SURE THAT LOCK TIMES NEVER EXCEED THE RESET PERIOD OF A TOKEN.

        // emit the ForcedWithdrawalStatusUpdated event.
        id.emitForcedWithdrawalStatusUpdatedEvent(uint256(0).asStubborn());

        return true;
    }

    /**
     * @notice Internal function for executing a forced withdrawal. Checks that the withdrawal
     * is enabled and the reset period has elapsed, then processes the withdrawal by burning
     * ERC6909 tokens and transferring the underlying tokens to the specified recipient.
     * @param id        The ERC6909 token identifier of the resource lock.
     * @param recipient The account that will receive the withdrawn tokens.
     * @param amount    The amount of tokens to withdraw.
     * @return          Whether the forced withdrawal was successfully executed.
     */
    function _processForcedWithdrawal(uint256 id, address recipient, uint256 amount) internal returns (bool) {
        // Derive the storage slot containing the time the withdrawal is enabled.
        uint256 cutoffTimeSlotLocation = _getCutoffTimeSlot(msg.sender, id);

        assembly ("memory-safe") {
            // Retrieve the value for the time the withdrawal is enabled.
            let withdrawableAt := sload(cutoffTimeSlotLocation)

            // Check that withdrawal is not disabled and that reset period has elapsed.
            if or(iszero(withdrawableAt), gt(withdrawableAt, timestamp())) {
                // revert PrematureWithdrawal(id)
                mstore(0, 0x9287bcb0)
                mstore(0x20, id)
                revert(0x1c, 0x24)

                // COULD PROVIDE ADDITIONAL INFORMATION IN THE REVERT, SUCH AS THE 'WITHDRAWABLE AT' TIME.
            }
        }

        // THE FORCED WITHDRAWAL WILL STAY ENABLED AFTER PROCESSING. SO AT ANY TIME, THE USER CAN CONTINUE TO WITHDRAW.
        // SO AT THE MOMENT, A FORCED WITHDRAWAL IS A STATE, THAT CAN STAY ENABLED WHICH REQUIRES TO DISCONTINUE ALL THE SUPPORT FOR THE TOKEN.
        // SHOULD A FORCED WITHDRAWAL NOT RATHER BE THIS "LAST RESORT" EXIT? SO ALL OF THE USERS TOKENS WILL GET WITHDRAWN AND NO DEPOSITS ARE ALLOWED ANYMORE DURING THE RESET PERIOD?

        // Process the withdrawal.
        return _withdraw(msg.sender, recipient, id, amount);
    }

    /**
     * @notice Internal view function for checking the forced withdrawal status. Returns the
     * status (disabled, pending, or enabled) based on whether a withdrawable timestamp exists
     * and whether it has elapsed.
     * @param account    The account to check the status for.
     * @param id         The ERC6909 token identifier of the resource lock.
     * @return status    The current ForcedWithdrawalStatus (disabled, pending, or enabled).
     * @return enabledAt The timestamp when forced withdrawal becomes possible.
     */
    function _getForcedWithdrawalStatus(address account, uint256 id) internal view returns (ForcedWithdrawalStatus status, uint256 enabledAt) {
        // Derive the storage slot containing the time the withdrawal is enabled.
        uint256 cutoffTimeSlotLocation = _getCutoffTimeSlot(account, id);

        assembly ("memory-safe") {
            // Retrieve the value for the time the withdrawal is enabled.
            enabledAt := sload(cutoffTimeSlotLocation)

            // Compute status: 0 if disabled, 1 if pending, 2 if enabled.
            status := mul(iszero(iszero(enabledAt)), sub(2, gt(enabledAt, timestamp())))
        }
    }

    /**
     * @notice Private pure function for computing the storage slot for a forced
     * withdrawal activation timestamp.
     * @param account                 The account that initiated the forced withdrawal.
     * @param id                      The ERC6909 token identifier of the resource lock.
     * @return cutoffTimeSlotLocation The storage slot for the activation timestamp.
     */
    function _getCutoffTimeSlot(address account, uint256 id) private pure returns (uint256 cutoffTimeSlotLocation) {
        assembly ("memory-safe") {
            // Retrieve the current free memory pointer.
            let m := mload(0x40)

            // Pack data for computing storage slot.
            mstore(0x14, account)
            mstore(0, _FORCED_WITHDRAWAL_ACTIVATIONS_SCOPE)
            mstore(0x34, id)

            //           -----------SLOT 1-----------   -----------SLOT 2----------- -----------SLOT 3-----------
            // master:  | [[00000000000][--32 bits--]] |        - 256 bits  -
            // account: |    - 160 bits  -     [[0000] | [---160 bits---]]
            // id:      |        - 256 bits  -         |   - 160 bits  - [----------|-256 bits-----------] - 96 bits -

            // WHY DO WE USE THIS MASTER -> ACCOUNT -> ID STRUCTURE? FOR THE BALANCE SLOT, WE USE ID -> ACCOUNT -> MASTER.
            // THIS WOULD ALLOW US TO SKIP THE EXTRA WORK WITH THE FREE MEMORY POINTER, AS WELL AS BEING MORE CONSISTENT.
            // WOULD IN THEORY ALLOW FOR AN INTERNAL FUNCTION THAT GENERATES ALL OF THESE SLOTS, BASED ON THE MASTER SLOT SEED.

            // Compute storage slot from packed data.
            cutoffTimeSlotLocation := keccak256(0x1c, 0x38)

            // Restore the free memory pointer.
            mstore(0x40, m)
        }
    }
}
