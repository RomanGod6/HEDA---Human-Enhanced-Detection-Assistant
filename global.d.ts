// global.d.ts
interface Window {
    electron: {
        fetchFirewallStats: () => Promise<{ totalPackets: number; maliciousPackets: number }>;
    };
}
