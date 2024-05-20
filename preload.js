const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
    fetchFirewallStats: () => ipcRenderer.invoke('fetch-firewall-stats'),
});
