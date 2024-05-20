import React from 'react';

interface TopIPsProps {
    title: string;
    data: { ip: string, count: number }[];
}

const TopIPs: React.FC<TopIPsProps> = ({ title, data }) => {
    return (
        <div className="rounded-lg border border-stroke bg-white p-6 shadow-lg dark:border-strokedark dark:bg-boxdark">
            <h4 className="text-2xl font-bold text-black dark:text-white mb-4">{title}</h4>
            <ul>
                {data.map((item, index) => (
                    <li key={index} className="text-lg font-medium text-gray-500 dark:text-gray-300">
                        {item.ip}: {item.count}
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default TopIPs;
