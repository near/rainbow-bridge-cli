const axios = require('axios');

(async function () {
  const projectId = ''
  const infuraUrl = `https://mainnet.infura.io/v3/${projectId}`

  const smartContractAddress = '0xdac17f958d2ee523a2206206994597c13d831ec7';
  const storageKeys = [
    "0x0000000000000000000000000000000000000000000000000000000000000000"
  ]
  const blockNumber = '0xC47670' // hex number or 'latest'

  const res = await axios.post(infuraUrl, {
    "jsonrpc": "2.0",
    "method": "eth_getProof",
    "params": [
      smartContractAddress,
      storageKeys,
      blockNumber
    ],
    "id": 1
  })

  console.log('res.data', res.data)
})()
