const ProcessManager = require('pm2')
const { spawnProcess } = require('./helpers')
const { Near2EthRelay } = require('rainbow-bridge-near2eth-block-relay')
const path = require('path')

class StartNear2EthRelayCommand {
  static async execute ({ daemon }) {
    if (daemon === 'true') {
      ProcessManager.connect((err) => {
        if (err) {
          console.log(
            'Unable to connect to the ProcessManager daemon! Please retry.'
          )
          return
        }
        spawnProcess('near2eth-relay', {
          name: 'near2eth-relay',
          script: path.join(__dirname, '../../index.js'),
          interpreter: 'node',
          error_file: '~/.rainbow/logs/near2eth-relay/err.log',
          out_file: '~/.rainbow/logs/near2eth-relay/out.log',
          args: ['start', 'near2eth-relay', ...RainbowConfig.getArgsNoDaemon()],
          wait_ready: true,
          kill_timeout: 60000,
          logDateFormat: 'YYYY-MM-DD HH:mm:ss.SSS'
        })
      })
    } else {
      const relay = new Near2EthRelay()
      await relay.initialize()
      await relay.run()
    }
  }
}

exports.StartNear2EthRelayCommand = StartNear2EthRelayCommand
