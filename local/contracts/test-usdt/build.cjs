// Local fixture compiler. Write artifacts outside the repository.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
if (process.argv.length !== 4) throw Error("usage: node build.cjs SOLC_MODULE OUTPUT");
const solc = require(path.resolve(process.argv[2]));
const source = fs.readFileSync(path.join(__dirname, "LocalUSDT.sol"), "utf8");
const input = {language: "Solidity", sources: {"LocalUSDT.sol": {content: source}},
  settings: {optimizer: {enabled: true, runs: 200},
    outputSelection: {"*": {"*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]}}}};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
if ((output.errors || []).some(e => e.severity === "error")) throw Error(JSON.stringify(output.errors));
const compiled = output.contracts["LocalUSDT.sol"].LocalUSDT;
const artifact = {contractName: "LocalUSDT", compiler: solc.version(),
  source_sha256: crypto.createHash("sha256").update(source).digest("hex"), abi: compiled.abi,
  bytecode: "0x" + compiled.evm.bytecode.object,
  deployedBytecode: "0x" + compiled.evm.deployedBytecode.object};
fs.mkdirSync(path.dirname(process.argv[3]), {recursive: true});
fs.writeFileSync(process.argv[3], JSON.stringify(artifact, null, 2) + "\n", {mode: 0o600});
console.log(JSON.stringify({compiler: artifact.compiler, source_sha256: artifact.source_sha256}));
