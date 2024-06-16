import React, { useEffect, useState } from 'react';
import CardDataStats from '../../components/CardDataStats';
import DefaultLayout from '../../layout/DefaultLayout';
import MapOne from '../../components/Maps/MapOne';
import ProtocolDistribution from '../../components/ProtocolDistribution';
import TopIPs from '../../components/TopIPs';

const FirewallDashboard: React.FC = () => {
  const [firewallStats, setFirewallStats] = useState({
    totalPackets: 0,
    maliciousPackets: 0,
    topSourceIPs: [],
    topDestinationIPs: [],
    protocolDistribution: [],
  });

  useEffect(() => {
    async function fetchData() {
      const stats = await window.electron.fetchFirewallStats();
      setFirewallStats(stats);
    }

    // Initial fetch
    fetchData();

    // Set interval to fetch data every 5 seconds
    const intervalId = setInterval(fetchData, 5000);

    // Clear interval on component unmount
    return () => clearInterval(intervalId);
  }, []);

  const totalPackets = firewallStats.totalPackets !== null ? firewallStats.totalPackets.toString() : '0';
  const maliciousPackets = firewallStats.maliciousPackets !== null ? firewallStats.maliciousPackets.toString() : '0';
  const benignPackets = (firewallStats.totalPackets - firewallStats.maliciousPackets) !== null ? (firewallStats.totalPackets - firewallStats.maliciousPackets).toString() : '0';

  return (
    <DefaultLayout>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 md:gap-6 xl:grid-cols-4 2xl:gap-7.5">
        <CardDataStats
          title='Packets Scanned'
          total={totalPackets}
          description="Total number of packets scanned."
          icon={
            <svg
              className="h-6 w-6 text-blue-500"
              fill="currentColor"
              viewBox="0 0 20 20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11V6a1 1 0 10-2 0v2H7a1 1 0 000 2h2v2a1 1 0 002 0V9h2a1 1 0 100-2h-2z"
                clipRule="evenodd"
              />
            </svg>
          }
        />
        <CardDataStats
          title='Malicious Packets'
          total={maliciousPackets}
          description="Total number of detected malicious packets."
          icon={
            <svg
              className="h-6 w-6 text-red-500"
              fill="currentColor"
              viewBox="0 0 20 20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zm-3.293-9.707a1 1 0 011.414 0L10 9.586l1.879-1.879a1 1 0 111.414 1.414L11.414 11l1.879 1.879a1 1 0 11-1.414 1.414L10 12.414l-1.879 1.879a1 1 0 11-1.414-1.414L8.586 11 6.707 9.121a1 1 0 010-1.414z"
                clipRule="evenodd"
              />
            </svg>
          }
        />
        <CardDataStats
          title='Benign Packets'
          total={benignPackets}
          description="Total number of benign packets."
          icon={
            <svg
              className="h-6 w-6 text-green-500"
              fill="currentColor"
              viewBox="0 0 20 20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11V6a1 1 0 10-2 0v2H7a1 1 0 000 2h2v2a1 1 0 002 0V9h2a1 1 0 100-2h-2z"
                clipRule="evenodd"
              />
            </svg>
          }
        />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 md:gap-6 2xl:grid-cols-4 2xl:gap-7.5">
        <TopIPs
          title="Top Source IPs"
          data={firewallStats.topSourceIPs || []}
        />
        <TopIPs
          title="Top Destination IPs"
          data={firewallStats.topDestinationIPs || []}
        />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 md:gap-6 2xl:grid-cols-4 2xl:gap-7.5">
        <ProtocolDistribution
          title="Protocol Distribution"
          data={firewallStats.protocolDistribution || []}
        />
      </div>

      <div className="mt-4 grid grid-cols-12 gap-4 md:mt-6 md:gap-6 2xl:mt-7.5 2xl:gap-7.5">
        <MapOne />
        <div className="col-span-12 xl:col-span-8">
          {/* Table example  */}
          {/* <TableOne /> */}
        </div>
        {/* Chat examples */}
        {/* <ChatCard /> */}
      </div>
    </DefaultLayout>
  );
};

export default FirewallDashboard;
