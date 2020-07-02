const ProcessManager = require('pm2');
const { spawnProcess } = require('./helpers');
const { RainbowConfig } = require('../../lib/config');

class StartGanacheNodeCommand {
    static async execute () {
        ProcessManager.connect((err) => {
            if (err) {
                console.log(
                    'Unable to connect to the ProcessManager daemon! Please retry.');
                return;
            }
            spawnProcess('ganache',
                {
                    name: 'ganache',
                    script: './scripts/start_ganache.sh',
                    error_file: '~/.rainbowup/logs/ganache/err.log',
                    out_file: '~/.rainbowup/logs/ganache/out.log',
                    args: [],
                    env: process.env,
                },
            );
        });
        RainbowConfig.setParam('eth-node-url', 'ws://localhost:9545');
        RainbowConfig.setParam('eth-master-sk', '0x2bdd21761a483f71054e14f5b827213567971c676928d9a1808cbfa4b7501200');
        RainbowConfig.setParam('eth2near-client-validate-ethash', 'false');
        RainbowConfig.saveConfig();
    }
}

exports.StartGanacheNodeCommand = StartGanacheNodeCommand;
