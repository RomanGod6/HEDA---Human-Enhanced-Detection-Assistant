const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
    fetchFirewallStats: () => ipcRenderer.invoke('fetch-firewall-stats'),
    fetchNotifications: () => ipcRenderer.invoke('fetch-notifications'),
    fetchNotificationById: (id) => ipcRenderer.invoke('fetch-notification-by-id', id),
    updateNotificationStatus: (id, isMalicious) => ipcRenderer.invoke('update-notification-status', id, isMalicious),
    onMaliciousPacket: (callback) => ipcRenderer.on('malicious_packet', callback),
    removeMaliciousPacketListener: (callback) => ipcRenderer.removeListener('malicious_packet', callback),

    // Add this line to expose the update-settings event
    updateSettings: (settings) => ipcRenderer.send('update-settings', settings),
});
