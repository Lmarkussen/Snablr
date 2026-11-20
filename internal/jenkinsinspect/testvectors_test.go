package jenkinsinspect

// Synthetic Jenkins home produced independently with pycryptodome from the
// Jenkins storage format: master.key text, hudson.util.Secret encrypted with
// SHA-256(master.key)[:16] in AES-ECB with the magic suffix, secrets in the
// current {AQAAAB...} form and the legacy AES-ECB form.
const (
	testMasterKey      = "719584624bb836b6236a1becf56c22dc204f37e5775eda542895a88c4c164c0d1db75893e8c8665e5060b05d5e03c68c963d5a3a6e7e0dba6b5e0b9cde858650d47a757afc624567a35e00bc93baf97509844ea9f01b34942bc0d21027dec95448b8566d21060bfec77f420446b1122cb903ec140fe946603dbdfbd49f4f0d5b"
	testHudsonSecret   = "2a48ecb47622d7a1f0658e86476cafc0141be5db61e0a69efd6b181d759cfd2788d942c4034a1f64c1620f4a24e505e77f5ff791b68a9877035b87636afa5ca0e1b7e5c1a734259abe24438b14a8520900b641af931fb7e783f81604452d74cee0898066781cff6bacf2f7874317dd925337a66d7fe59fb612d3fa2abc47bbd1d2d4be2b095a6c6045002da468b7584008cd14c3680bbbc9488887ed85f67bab1c9a40e40dbfba5694b4acd655199517b4910679134ac0dc68c697b9ebd0ba399f578d90291391be2206338b78dc03e73dc97593ddd5bedd72b1ba638916443326f61db78ed86f33dfb315c614ed8c62d51ca9348ed0ba6462afbdb56f5bda00eff391c1b7208a1765c6b4c81f61f36f"
	testPasswordNew    = "{AQAAABAAAAAgRTOyIOxKqSP4le7yKQiB15kMYNt4ur7ytAWWJmRnHAIjYe5DVqa2Miu2tWR9nubv}" // "Tr4in-Jenk-2026!"
	testSecretNew      = "{AQAAABAAAAAglGT8e3wttIqkfBeyskezCUGpeXBlLjyZw9cEzNZwWS1Fbm2+VcAOrfNzEHZZGF3d}" // "build-token-SYNTHETIC-8842"
	testPasswordLegacy = "8rOCUkKBP32Tyo+eKF9MQluTluCio1v90QMzzMhXaAI="                                   // "Legacy-Jenk-0417"
	testOtherKeyValue  = "{AQAAABAAAAAQtF5XvJAJtUVfgbD38nDEl+TXfZXE8RtRWVeMBFGM9fY=}"                     // encrypted under another key
)
