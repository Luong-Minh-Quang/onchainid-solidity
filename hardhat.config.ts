import "@nomicfoundation/hardhat-toolbox";
import { HardhatUserConfig } from "hardhat/config";
import 'solidity-coverage';
import "@nomiclabs/hardhat-solhint";
import * as dotenv from 'dotenv';
dotenv.config();

import "./tasks/add-claim.task";
import "./tasks/add-key.task";
import "./tasks/deploy-identity.task";
import "./tasks/deploy-proxy.task";
import "./tasks/remove-claim.task";
import "./tasks/remove-key.task";
import "./tasks/revoke.task";
import "./tasks/deploy-claim-issuer.task"
const config: HardhatUserConfig = {
  solidity: "0.8.17",
  networks: {
    sepolia: {
      url: process.env.SEPOLIA_URL || "",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY,
  },
};

export default config;
