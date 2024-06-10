import { IpcRendererEvent } from 'electron';

export interface AppNotification {
    id: number;
    log_id: number;
    notification_timestamp: string;
    src_ip: string;
    dst_ip: string;
    details: string;
}

export interface PacketDetails {
    id: number;
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    protocol: string;
    payload: string;
    timestamp: string;
}

export interface ElectronAPI {
    fetchFirewallStats: () => Promise<any>;
    fetchNotifications: () => Promise<AppNotification[]>;
    fetchNotificationById: (id: number) => Promise<AppNotification>;
    updateNotificationStatus: (id: number, isMalicious: boolean) => Promise<any>;
    onMaliciousPacket: (callback: (event: any, data: AppNotification) => void) => void;
    removeMaliciousPacketListener: (callback: (event: any, data: AppNotification) => void) => void;
    updateSettings: (settings: { automaticThreatResponse: boolean; selectedOption: string }) => void; // Add this line
}

declare global {
    interface Window {
        electron: ElectronAPI;
    }
}

export { }; // This ensures the file is treated as a module
