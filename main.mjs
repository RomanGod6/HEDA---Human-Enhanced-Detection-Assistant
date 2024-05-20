import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import sqlite3 from 'sqlite3';
import { spawn } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            enableRemoteModule: false,
            nodeIntegration: false,
        },
    });

    mainWindow.loadURL('http://localhost:5173/');
    mainWindow.webContents.openDevTools();
}

function runPythonScript() {
    const pythonProcess = spawn('python', ['./Python/main.py']);

    pythonProcess.stdout.on('data', (data) => {
        console.log(`stdout: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`stderr: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python script exited with code ${code}`);
    });
}

app.whenReady().then(() => {
    createWindow();
    runPythonScript();
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

// SQLite Database Setup
const dbPath = path.join(__dirname, 'network_traffic.db');
const db = new sqlite3.Database(dbPath);

ipcMain.handle('fetch-firewall-stats', (event) => {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.get('SELECT COUNT(*) AS totalPackets, SUM(malicious) AS maliciousPackets FROM firewall_logs', [], (err, row) => {
                if (err) {
                    console.error('Database error:', err);
                    reject(err);
                    return;
                }

                const stats = {
                    totalPackets: row.totalPackets,
                    maliciousPackets: row.maliciousPackets,
                    topSourceIPs: [],
                    topDestinationIPs: [],
                    protocolDistribution: [],
                };

                db.all('SELECT src_ip AS ip, COUNT(*) AS count FROM firewall_logs GROUP BY src_ip ORDER BY count DESC LIMIT 10', [], (err, rows) => {
                    if (err) {
                        console.error('Database error:', err);
                        reject(err);
                        return;
                    }
                    stats.topSourceIPs = rows;

                    db.all('SELECT dst_ip AS ip, COUNT(*) AS count FROM firewall_logs GROUP BY dst_ip ORDER BY count DESC LIMIT 10', [], (err, rows) => {
                        if (err) {
                            console.error('Database error:', err);
                            reject(err);
                            return;
                        }
                        stats.topDestinationIPs = rows;

                        db.all('SELECT protocol, COUNT(*) AS count FROM firewall_logs GROUP BY protocol', [], (err, rows) => {
                            if (err) {
                                console.error('Database error:', err);
                                reject(err);
                                return;
                            }
                            stats.protocolDistribution = rows;

                            resolve(stats);
                        });
                    });
                });
            });
        });
    });
});
