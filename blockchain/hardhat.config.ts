import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthersPlugin
    from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default defineConfig({
    plugins: [
        hardhatToolboxMochaEthersPlugin,
    ],

    solidity: {
        version: "0.8.24",

        settings: {
            optimizer: {
                enabled: true,
                runs: 200,
            },
        },
    },
});