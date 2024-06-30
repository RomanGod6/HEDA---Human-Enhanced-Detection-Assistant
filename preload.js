const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electron', {
    fetchFirewallStats: () => ipcRenderer.invoke('fetch-firewall-stats'),
    fetchNotifications: () => ipcRenderer.invoke('fetch-notifications'),
    fetchNotificationById: (id) => ipcRenderer.invoke('fetch-notification-by-id', id),
    updateNotificationStatus: (id, isMalicious) => ipcRenderer.invoke('update-notification-status', id, isMalicious),
    onMaliciousPacket: (callback) => ipcRenderer.on('malicious_packet', callback),
    removeMaliciousPacketListener: (callback) => ipcRenderer.removeListener('malicious_packet', callback),
    updateSettings: (settings) => ipcRenderer.send('update-settings', settings),
    fetchPacketLogs: ({ page, pageSize, search, searchColumns }) => ipcRenderer.invoke('fetch-packet-logs', { page, pageSize, search, searchColumns }),
    saveSecurityAction: (action) => ipcRenderer.invoke('save-security-action', action),
    fetchSecurityActions: () => ipcRenderer.invoke('fetch-security-actions'),
    fetchSettings: () => ipcRenderer.invoke('fetch-settings'),
    fetchWhitelist: () => ipcRenderer.invoke('fetch-whitelist'),
    addToWhitelist: (ipAddress) => ipcRenderer.invoke('add-to-whitelist', ipAddress),
    removeFromWhitelist: (id) => ipcRenderer.invoke('remove-from-whitelist', id),
    markAllNotificationsAsViewed: () => ipcRenderer.invoke('mark-all-notifications-as-viewed'),
});
