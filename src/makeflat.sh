rm -rf flat
mkdir flat
forge flatten -o flat/AccountGuardian.sol AccountGuardian.sol
forge flatten -o flat/AccountProxy.sol AccountProxy.sol
forge flatten -o flat/AccountV3Modified.sol AccountV3Modified.sol
forge flatten -o flat/AccountV3ModifiedUpgradable.sol AccountV3ModifiedUpgradable.sol
forge flatten -o flat/Src.sol Src.sol
