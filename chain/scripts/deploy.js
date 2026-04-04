const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with:", deployer.address);
  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");

  const Registry = await ethers.getContractFactory("VoiceProofRegistry");
  const registry  = await Registry.deploy();
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log("✅ VoiceProofRegistry deployed to:", address);

  // server/.env の CONTRACT_ADDRESS を自動更新
  const envPath = path.join(__dirname, "../../server/.env");
  if (fs.existsSync(envPath)) {
    let env = fs.readFileSync(envPath, "utf8");
    env = env.replace(/^CONTRACT_ADDRESS=.*/m, `CONTRACT_ADDRESS=${address}`);
    fs.writeFileSync(envPath, env);
    console.log("✅ server/.env の CONTRACT_ADDRESS を更新しました");
  }
}

main().catch(e => { console.error(e); process.exit(1); });
